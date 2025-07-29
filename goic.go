package goic

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var (
	// ErrProviderState is error for invalid request state
	ErrProviderState = fmt.Errorf("goic provider: invalid request state")

	// ErrProviderSupport is error for unsupported provider
	ErrProviderSupport = fmt.Errorf("goic provider: unsupported provider")

	// ErrTokenEmpty is error for empty token
	ErrTokenEmpty = fmt.Errorf("goic id_token: empty token")

	// ErrTokenInvalid is error for invalid token
	ErrTokenInvalid = fmt.Errorf("goic id_token: invalid id_token")

	// ErrRefreshTokenInvalid is error for invalid token
	ErrRefreshTokenInvalid = fmt.Errorf("goic id_token: invalid refresh_token")

	// ErrTokenClaims is error for invalid token claims
	ErrTokenClaims = fmt.Errorf("goic id_token: invalid id_token claims")

	// ErrTokenNonce is error for invalid noce
	ErrTokenNonce = fmt.Errorf("goic id_token: invalid nonce")

	// ErrTokenAud is error for invalid audience
	ErrTokenAud = fmt.Errorf("goic id_token: invalid audience")

	// ErrTokenAlgo is error for unsupported signing algo
	ErrTokenAlgo = fmt.Errorf("goic id_token: unsupported signing algo")

	// ErrTokenKey is error for undetermined signing key
	ErrTokenKey = fmt.Errorf("goic id_token: can't determine signing key")

	// ErrTokenAccessKey is error for invalid access_token
	ErrTokenAccessKey = fmt.Errorf("goic id_token: invalid access_token")

	// ErrSignOutRedir is error for invalid post sign-out redirect uri
	ErrSignOutRedir = fmt.Errorf("goic sign-out: post redirect uri is invalid")
)

var (
	// stateLength is state query param length
	stateLength = 16

	// nonceLength is nonce query param length
	nonceLength = 20
)

// UserCallback defines signature for post user verification callback
type UserCallback func(t *Token, u *User, w http.ResponseWriter, r *http.Request)

// Goic is the main program
type Goic struct {
	providers    map[string]*Provider
	userCallback UserCallback
	states       map[string]string
	URIPrefix    string
	sLock        sync.RWMutex
	verbose      bool
}

// New gives new GOIC instance
func New(uri string, verbose bool) *Goic {
	providers := make(map[string]*Provider)
	states := make(map[string]string)

	return &Goic{URIPrefix: uri, verbose: verbose, providers: providers, states: states}
}

// NewProvider registers a new OpenID provider by name
// It also preloads the well known config and jwks keys
func (g *Goic) NewProvider(name, uri string, loader ...func() (*WellKnown, error)) *Provider {
	if p, ok := g.providers[name]; ok {
		g.logIf("goic provider %s: already set", name)
		return p
	}

	u, err := url.Parse(uri)
	if err != nil {
		log.Fatalf("goic provider %s: url invalid: %s: %v", name, uri, err.Error())
	}

	p := &Provider{Name: name, URL: uri, Scope: "openid", host: u.Host}
	if len(loader) > 0 && loader[0] != nil {
		p.WellKnowner = loader[0]
	}
	return g.AddProvider(p)
}

// AddProvider adds a Provider to Goic only if it can be discovered
func (g *Goic) AddProvider(p *Provider, async ...bool) *Provider {
	if p, ok := g.providers[p.Name]; ok {
		g.logIf("goic provider %s: already set", p.Name)
		return p
	}
	if p.WellKnowner == nil {
		p.WellKnowner = p.getWellKnown
	}

	if !p.discovered {
		p.wellKnown, p.err = p.WellKnowner()
		if p.err != nil && (len(async) == 0 || !async[0]) {
			log.Fatalf("goic provider %s: cannot load well-known configuration: %s", p.Name, p.err.Error())
		}
	}
	if p.err != nil {
		return p // return without assigning
	}

	g.providers[p.Name] = p
	go func() { // Keep wellknown in sync
		for range time.NewTicker(24 * time.Hour).C {
			p.discovered = false
			p.wellKnown, p.err = p.WellKnowner()
		}
	}()
	return p
}

// GetProvider returns Provider by name or nil if not existent
func (g *Goic) GetProvider(name string) *Provider {
	if p, ok := g.providers[name]; ok {
		return p
	}
	return nil
}

// Supports checks if a given provider name is supported
func (g *Goic) Supports(name string) bool {
	_, ok := g.providers[name]
	return ok
}

// RequestAuth is the starting point of OpenID flow
func (g *Goic) RequestAuth(p *Provider, state, nonce, redir string, res http.ResponseWriter, req *http.Request) error {
	if !g.Supports(p.Name) {
		return ErrProviderSupport
	}

	redirect := AuthRedirectURL(p, state, nonce, redir)
	if redirect == "" {
		return ErrProviderSupport
	}
	http.Redirect(res, req, redirect, http.StatusFound)
	return nil
}

// AuthRedirectURL gives the full auth redirect URL for the provider
// It returns empty string when there is an error
func AuthRedirectURL(p *Provider, state, nonce, redir string) string {
	redirect, err := http.NewRequest("GET", p.GetURI("auth"), nil)
	if err != nil {
		return ""
	}

	qry := redirect.URL.Query()
	qry.Add("response_type", "code")
	if p.ResType != "" {
		qry.Set("response_type", p.ResType)
	}

	qry.Add("redirect_uri", redir)
	qry.Add("client_id", p.clientID)
	qry.Add("scope", p.Scope)
	qry.Add("state", state)
	qry.Add("nonce", nonce)
	redirect.URL.RawQuery = qry.Encode()

	query := ""
	if p.QueryFn != nil {
		query = "&" + p.QueryFn()
	}

	return redirect.URL.String() + query
}

// checkState checks if given state is valid (i.e. known)
func (g *Goic) checkState(state string) (string, error) {
	if state == "" || len(state) != stateLength {
		return "", ErrProviderState
	}

	g.sLock.Lock()
	defer g.sLock.Unlock()

	nonce, ok := g.states[state]
	if !ok {
		return "", ErrProviderState
	}

	delete(g.states, state)
	return nonce, nil
}

// Authenticate tries to authenticate a user by given code and nonce
// It is where token is requested and validated
func (g *Goic) Authenticate(p *Provider, codeOrTok, nonce, redir string) (tok *Token, err error) {
	tok = &Token{Provider: p.Name}
	if !g.Supports(p.Name) {
		return tok, ErrProviderSupport
	}

	isCode := p.ResType == "" || strings.Contains(" "+p.ResType+" ", " code ")
	// get token from code or just parse token
	if isCode {
		tok, err = g.getToken(p, codeOrTok, redir, "authorization_code")
	} else {
		tok, err = parseToken([]byte(codeOrTok), tok)
	}

	if err != nil {
		return tok, fmt.Errorf("get token: %w", err)
	}
	if err := g.verifyToken(p, tok, nonce); err != nil {
		return tok, fmt.Errorf("verify token: %w", err)
	}

	return tok, nil
}

// getToken actually gets token from Provider via wellKnown.TokenURI
func (g *Goic) getToken(p *Provider, code, redir, grant string) (tok *Token, err error) {
	tok = &Token{Provider: p.Name}

	qry := url.Values{}
	qry.Add("grant_type", grant)
	if grant == "authorization_code" {
		qry.Add("code", code)
		qry.Add("redirect_uri", redir)
	} else {
		qry.Add("refresh_token", code)
	}
	qry.Add("client_id", p.clientID)
	qry.Add("client_secret", p.clientSecret)

	req, err := http.NewRequest("POST", p.GetURI("token"), strings.NewReader(qry.Encode()))
	if err != nil {
		return tok, err
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return tok, err
	}
	defer res.Body.Close()

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return tok, err
	}

	return parseToken(body, tok)
}

func parseToken(tokByte []byte, tok *Token) (*Token, error) {
	if err := json.Unmarshal(tokByte, &tok); err != nil {
		return tok, err
	}
	if tok.IDToken == "" {
		return tok, ErrTokenEmpty
	}

	if tok.Err != "" {
		msg := tok.Err
		if tok.ErrDesc != "" {
			msg += ": " + tok.ErrDesc
		}
		return tok, fmt.Errorf(msg)
	}
	return tok, nil
}

// verifyToken checks and verifies authenticity and ownership of Token
func (g *Goic) verifyToken(p *Provider, tok *Token, nonce string) (err error) {
	// Data verification
	if err = tok.VerifyClaims(nonce, p.clientID); err != nil {
		return err
	}

	// Signature verification
	_, err = jwt.ParseWithClaims(tok.IDToken, tok.Claims, func(t *jwt.Token) (any, error) {
		alg := t.Header["alg"].(string)
		al2 := alg[0:2]
		if al2 == "HS" {
			return []byte(p.clientSecret), nil
		}
		if al2 != "RS" && al2 != "ES" {
			return nil, ErrTokenAlgo
		}

		for _, key := range p.wellKnown.jwks.Keys {
			kid := key.Kid == t.Header["kid"]
			if kid && key.Kty == "EC" && key.Alg == alg {
				return &ecdsa.PublicKey{X: ParseModulo(key.X), Y: ParseModulo(key.Y), Curve: GetCurve(key.Crv)}, nil
			}
			if kid && (key.Kty == "RSA" || key.Alg == alg) {
				return &rsa.PublicKey{E: ParseExponent(key.E), N: ParseModulo(key.N)}, nil
			}
		}

		return nil, ErrTokenKey
	})

	return err
}

// MiddlewareHandler is wrapper for http.Handler that adds OpenID support
func (g *Goic) MiddlewareHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
		if strings.Index(req.URL.Path, g.URIPrefix) != 0 {
			next.ServeHTTP(res, req)
		} else {
			g.process(res, req)
		}
	})
}

// MiddlewareFunc is wrapper for http.HandlerFunc that adds OpenID support
func (g *Goic) MiddlewareFunc(next http.HandlerFunc) http.HandlerFunc {
	return func(res http.ResponseWriter, req *http.Request) {
		if strings.Index(req.URL.Path, g.URIPrefix) != 0 {
			next(res, req)
		} else {
			g.process(res, req)
		}
	}
}

// process is the actual processor of OpenID flow
func (g *Goic) process(res http.ResponseWriter, req *http.Request) {
	defer trapError(res)

	name := req.URL.Path[1+len(g.URIPrefix):]
	if !g.Supports(name) {
		g.errorHTML(res, ErrProviderSupport, "", "process")
		return
	}

	qry, redir := req.URL.Query(), currentURL(req, false)
	restart := ` (<a href="` + redir + `">restart</a>)`
	if msg := qry.Get("error"); msg != "" {
		if desc := qry.Get("error_description"); desc != "" {
			msg += ": " + desc
		}
		g.errorHTML(res, fmt.Errorf(msg), restart, "callback")
		return
	}

	code, state := qry.Get("code"), qry.Get("state")
	p := g.providers[name]
	if code == "" {
		state, nonce := g.initStateAndNonce()
		if err := g.RequestAuth(p, state, nonce, redir, res, req); err != nil {
			g.errorHTML(res, err, restart, "request auth")
		}
		return
	}

	nonce, err := g.checkState(state)
	if err != nil {
		g.errorHTML(res, err, restart, "checkState")
		return
	}

	tok, err := g.Authenticate(p, code, nonce, redir)
	if err != nil {
		g.errorHTML(res, err, restart, "authenticate")
		return
	}

	if g.userCallback == nil {
		_, _ = res.Write([]byte("OK, the auth flow is complete. However, backend is yet to request userinfo"))
		return
	}

	g.userCallback(tok, g.UserInfo(tok), res, req)
}

// initStateAndNonce inits one time state and nonce
func (g *Goic) initStateAndNonce() (string, string) {
	nonce, state := RandomString(nonceLength), RandomString(stateLength)

	g.sLock.Lock()
	for {
		if _, ok := g.states[state]; !ok {
			break
		}
		state = RandomString(stateLength)
	}

	g.states[state] = nonce
	g.sLock.Unlock()

	return state, nonce
}

// UserCallback sets a callback for post user verification
func (g *Goic) UserCallback(cb UserCallback) *Goic {
	g.userCallback = cb
	return g
}

// UserInfo loads user info when given a Token
// Error if any is embedded inside User.Error
func (g *Goic) UserInfo(tok *Token) *User {
	user := &User{}
	if !g.Supports(tok.Provider) {
		return user.withError(ErrProviderSupport)
	}

	if tok.AccessToken == "" {
		return user.withError(ErrTokenAccessKey)
	}

	p := g.providers[tok.Provider]
	if p.GetURI("userinfo") == "" {
		return user.FromClaims(tok.Claims)
	}

	req, err := http.NewRequest("GET", p.GetURI("userinfo"), nil)
	if err != nil {
		return user.withError(err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+tok.AccessToken)

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return user.withError(err)
	}
	defer res.Body.Close()

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return user.withError(err)
	}

	if err := json.Unmarshal(body, &user); err != nil {
		return user.withError(err)
	}

	return user
}

// RefreshToken gets new access token using the refresh token
func (g *Goic) RefreshToken(tok *Token) (*Token, error) {
	name := tok.Provider
	if !g.Supports(name) {
		return nil, ErrProviderSupport
	}
	if tok.RefreshToken == "" {
		return nil, ErrRefreshTokenInvalid
	}

	p := g.providers[name]
	t, err := g.getToken(p, tok.RefreshToken, "", "refresh_token")
	if err == ErrTokenEmpty {
		err = nil
	}

	return t, err
}

// SignOut signs out the Token from OpenID Provider and then redirects to given URI
// Redirect URI must be preconfigured in OpenID Provider already
func (g *Goic) SignOut(tok *Token, redir string, res http.ResponseWriter, req *http.Request) error {
	if redir != "" {
		if _, err := url.Parse(redir); err != nil {
			return ErrSignOutRedir
		}
	}

	p, ok := g.providers[tok.Provider]
	if !ok || !p.CanSignOut() {
		return ErrProviderSupport
	}

	redirect, err := http.NewRequest("GET", p.GetURI("signout"), nil)
	if err != nil {
		return err
	}

	tk, qry := tok.AccessToken, redirect.URL.Query()
	if tk == "" && tok.RefreshToken != "" {
		tk = tok.RefreshToken
	}
	if tk != "" {
		qry.Add("id_token_hint", tk)
	}
	if redir != "" {
		qry.Add("post_logout_redirect_uri", redir)
	}

	redirect.URL.RawQuery = qry.Encode()
	http.Redirect(res, req, redirect.URL.String(), http.StatusFound)
	return nil
}

// RevokeToken revokes a Token so that it is no longer usable
func (g *Goic) RevokeToken(tok *Token) error {
	p, ok := g.providers[tok.Provider]
	if !ok || !p.CanRevoke() {
		return ErrProviderSupport
	}

	tk, hint := tok.AccessToken, "access_token"
	if tk == "" && tok.RefreshToken != "" {
		tk, hint = tok.RefreshToken, "refresh_token"
	}
	if tk == "" {
		return ErrTokenAccessKey
	}

	qry := url.Values{}
	qry.Add("token", tk)
	qry.Add("token_type_hint", hint)

	req, err := http.NewRequest("POST", p.GetURI("revoke"), strings.NewReader(qry.Encode()))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", p.AuthBasicHeader())
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return err
	}

	var revoke map[string]any
	if err := json.Unmarshal(body, &revoke); err != nil {
		return err
	}
	if e, ok := revoke["error"].(map[string]string); ok {
		if msg, ok := e["message"]; ok {
			return fmt.Errorf(msg)
		}
	}
	return nil
}

// logIf logs if verbose is set
func (g *Goic) logIf(s string, v ...any) {
	if g.verbose {
		log.Printf(s, v...)
	}
}

// errorHTML shows error page with html like text
func (g *Goic) errorHTML(res http.ResponseWriter, err error, h, label string) {
	g.logIf("[err] %s: %v\n", label, err)

	res.Header().Set("Content-Type", "text/html; charset=utf-8")
	res.Header().Set("X-Content-Type-Options", "nosniff")
	res.WriteHeader(http.StatusInternalServerError)

	_, _ = res.Write([]byte(err.Error() + h))
}

// UnsetState unsets state from memory
func (g *Goic) UnsetState(s string) {
	g.sLock.Lock()
	delete(g.states, s)
	g.sLock.Unlock()
}
