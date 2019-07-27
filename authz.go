package authz

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/caddyserver/caddy"
	"github.com/caddyserver/caddy/caddyhttp/httpserver"
	"github.com/casbin/casbin"
	jwt "github.com/dgrijalva/jwt-go"
	jwtcaddy "github.com/BTBurke/caddy-jwt"
)

/* ************************************************************************** */
/* Extraction JWT */

type TokenSource interface {
	// If the returned string is empty, the token was not found.
	// So far any implementation does not return errors.
	ExtractToken(r *http.Request) string
}

// Extracts a token from the Authorization header in the form `Bearer <JWT Token>`
type HeaderTokenSource struct {
	HeaderName string
}

func (hts *HeaderTokenSource) ExtractToken(r *http.Request) string {
	jwtHeader := strings.Split(r.Header.Get("Authorization"), " ")
	if jwtHeader[0] == hts.HeaderName && len(jwtHeader) == 2 {
		return jwtHeader[1]
	}
	return ""
}

// Extracts a token from a cookie named `CookieName`.
type CookieTokenSource struct {
	CookieName string
}

func (cts *CookieTokenSource) ExtractToken(r *http.Request) string {
	jwtCookie, err := r.Cookie(cts.CookieName)
	if err == nil {
		return jwtCookie.Value
	}
	return ""
}

// Extracts a token from a URL query parameter of the form https://example.com?ParamName=<JWT token>
type QueryTokenSource struct {
	ParamName string
}

func (qts *QueryTokenSource) ExtractToken(r *http.Request) string {
	jwtQuery := r.URL.Query().Get(qts.ParamName)
	if jwtQuery != "" {
		return jwtQuery
	}
	return ""
}

var (
	// Default TokenSources to be applied in the given order if the
	// user did not explicitly configure them via the token_source option
	DefaultTokenSources = []TokenSource{
		&HeaderTokenSource{
			HeaderName: "Bearer",
		},
		&CookieTokenSource{
			CookieName: "jwt_token",
		},
		&QueryTokenSource{
			ParamName: "token",
		},
	}
)

type UserInfo struct {
	Sub       string   `json:"sub"`
	Picture   string   `json:"picture,omitempty"`
	Name      string   `json:"name,omitempty"`
	Email     string   `json:"email,omitempty"`
	Origin    string   `json:"origin,omitempty"`
	Expiry    int64    `json:"exp,omitempty"`
	Refreshes int      `json:"refs,omitempty"`
	Domain    string   `json:"domain,omitempty"`
	Groups    []string `json:"groups,omitempty"`
}

// Valid lets us use the user info as Claim for jwt-go.
// It checks the token expiry.
func (u UserInfo) Valid() error {
	if u.Expiry < time.Now().Unix() {
		return fmt.Errorf("token expired")
	}
	return nil
}

func (u UserInfo) AsMap() map[string]interface{} {
	m := map[string]interface{}{
		"sub": u.Sub,
	}
	if u.Picture != "" {
		m["picture"] = u.Picture
	}
	if u.Name != "" {
		m["name"] = u.Name
	}
	if u.Email != "" {
		m["email"] = u.Email
	}
	if u.Origin != "" {
		m["origin"] = u.Origin
	}
	if u.Expiry != 0 {
		m["exp"] = u.Expiry
	}
	if u.Refreshes != 0 {
		m["refs"] = u.Refreshes
	}
	if u.Domain != "" {
		m["domain"] = u.Domain
	}
	if len(u.Groups) > 0 {
		m["groups"] = u.Groups
	}
	return m
}

/* ************************************************************************** */

// Authorizer is a middleware for filtering clients based on their ip or country's ISO code.
type Authorizer struct {
	Next     httpserver.Handler
	Enforcer *casbin.Enforcer
}

// Init initializes the plugin
func init() {
	caddy.RegisterPlugin("authz", caddy.Plugin{
		ServerType: "http",
		Action:     Setup,
	})
}

// GetConfig gets the config path that corresponds to c.
func GetConfig(c *caddy.Controller) (string, string) {
	modelPath := ""
	policyPath := ""
	for c.Next() {              // skip the directive name
		if !c.NextArg() {       // expect at least one value
			return c.ArgErr().Error(), policyPath   // otherwise it's an error
		}
		modelPath = c.Val()        // use the value

		if !c.NextArg() {       // expect at least one value
			return modelPath, c.ArgErr().Error()   // otherwise it's an error
		}
		policyPath = c.Val()        // use the value
	}
	return modelPath, policyPath
}

// Setup parses the Casbin configuration and returns the middleware handler.
func Setup(c *caddy.Controller) error {
	modelPath, policyPath := GetConfig(c)
	e := casbin.NewEnforcer(modelPath, policyPath)

	// Create new middleware
	newMiddleWare := func(next httpserver.Handler) httpserver.Handler {
		return &Authorizer{
			Next:     next,
			Enforcer: e,
		}
	}
	// Add middleware
	cfg := httpserver.GetConfig(c)
	cfg.AddMiddleware(newMiddleWare)

	return nil
}

// ServeHTTP serves the request.
func (a Authorizer) ServeHTTP(w http.ResponseWriter, r *http.Request) (int, error) {
	if !a.CheckPermission(r) {
		w.WriteHeader(403)
		return http.StatusForbidden, nil
	} else {
		return a.Next.ServeHTTP(w, r)
	}
}

// GetUserName gets the user name from the request.
// Currently, only HTTP basic authentication is supported
func (a *Authorizer) GetUserName(r *http.Request) (string, error) {
	uToken, err := ExtractToken(r)
	if err != nil {
		return "", fmt.Errorf("ExtractToken error")
	}

	var vToken *jwt.Token
	vToken, err = ValidateToken(uToken)
	if err != nil || vToken == nil {
		return "", fmt.Errorf("ValidateToken error")
	}
	claims, _ := vToken.Claims.(*UserInfo)
	return claims.AsMap()["sub"], nil
}

// CheckPermission checks the user/method/path combination from the request.
// Returns true (permission granted) or false (permission forbidden)
func (a *Authorizer) CheckPermission(r *http.Request) bool {
	user, err := a.GetUserName(r)
	fmt.Println("user")
	fmt.Println(user)
	if err != nil {
		user = "guest"
	}
	fmt.Println(user)
	method := r.Method
	path := r.URL.Path
	return a.Enforcer.Enforce(user, path, method)
}


func ExtractToken(r *http.Request) (string, error) {
	effectiveTss := DefaultTokenSources
	for _, tss := range effectiveTss {
		token := tss.ExtractToken(r)
		if token != "" {
			return token, nil
		}
	}

	return "", fmt.Errorf("no token found")
}


func ValidateToken(uToken string) (*jwt.Token, error) {
	if len(uToken) == 0 {
		return nil, fmt.Errorf("Token length is zero")
	}
	parser:= new(jwt.Parser)
	token, parts, err := parser.ParseUnverified(uToken, &UserInfo{})

	if err != nil {
		return nil, err
	}

	return token, nil
}