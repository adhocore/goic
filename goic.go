package goic

import (
	"bytes"
	"crypto/rsa"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"github.com/golang-jwt/jwt/v4"
)

var (
	// ErrProviderState is error for invalid request state
	ErrProviderState = errors.New("goic provider: invalid request state")

	// ErrProviderSupport is error for unsupported provider
	ErrProviderSupport = errors.New("goic provider: unsupported provider")

	// ErrTokenEmpty is error for empty token
	ErrTokenEmpty = errors.New("goic id_token: empty token")

	// ErrTokenInvalid is error for invalid token
	ErrTokenInvalid = errors.New("goic id_token: invalid id_token")

	// ErrTokenClaims is error for invalid token claims
	ErrTokenClaims = errors.New("goic id_token: invalid id_token claims")

	// ErrTokenNonce is error for invalid noce
	ErrTokenNonce = errors.New("goic id_token: invalid nonce")

	// ErrTokenAud is error for invalid audience
	ErrTokenAud = errors.New("goic id_token: invalid audience")

	// ErrTokenAlgo is error for unsupported signing algo
	ErrTokenAlgo = errors.New("goic id_token: unsupported signing algo")

	// ErrTokenKey is error for undetermined signing key
	ErrTokenKey = errors.New("goic id_token: can't determine signing key")

	// ErrTokenAccessKey is error for invalid access_token
	ErrTokenAccessKey = errors.New("goic id_token: invalid access_token")
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
	URIPrefix    string
	verbose      bool
	providers    map[string]*Provider
	userCallback UserCallback
	sLock        sync.RWMutex
	states       map[string]string
}

// Token represents token structure from well known token endpoint
type Token struct {
	Err          string `json:"error"`
	ErrDesc      string `json:"error_description"`
	AuthURI      string `json:"authorization_endpoint"`
	IDToken      string `json:"id_token"`
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	Provider     string
	idToken      map[string]interface{}
}

// User represents user from well know user info endpoint
type User struct {
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified,omitempty"`
	FamilyName    string `json:"family_name,omitempty"`
	GivenName     string `json:"given_name,omitempty"`
	Locale        string `json:"locale,omitempty"`
	Name          string `json:"name"`
	Picture       string `json:"picture,omitempty"`
	Subject       string `json:"sub,omitempty"`
	Error         error
}

// New gives new GOIC instance
func New(uri string, verbose bool) *Goic {
	providers := make(map[string]*Provider)
	states := make(map[string]string)

	return &Goic{URIPrefix: uri, verbose: verbose, providers: providers, states: states}
}

// NewProvider adds a new OpenID provider by name
// It also preloads the well known config and jwks keys
func (g *Goic) NewProvider(name, uri string) *Provider {
	if p, ok := g.providers[name]; ok {
		return p
	}

	u, err := url.Parse(uri)
	if err != nil {
		log.Fatalf("goic provider %s: url invalid: %s: %v", name, uri, err.Error())
	}

	p := &Provider{Name: name, URL: uri, Scope: "openid", host: u.Host}
	if _, err := p.getWellKnown(); err != nil {
		log.Fatalf("goic provider %s: cannot load well-known configuration: %s", name, err.Error())
	}

	g.providers[p.Name] = p
	return p
}

// Supports checks if a given provider name is supported
func (g *Goic) Supports(name string) bool {
	_, ok := g.providers[name]
	return ok
}

// RequestAuth is the starting point of OpenID flow
func (g *Goic) RequestAuth(name string, res http.ResponseWriter, req *http.Request) error {
	p := g.providers[name]

	redir, err := http.NewRequest("GET", p.wellKnown.AuthURI, nil)
	if err != nil {
		return err
	}

	qry := redir.URL.Query()
	qry.Add("response_type", "code")
	qry.Add("redirect_uri", currentURL(req, false))
	qry.Add("client_id", p.clientID)
	qry.Add("scope", p.Scope)

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

	qry.Add("state", state)
	qry.Add("nonce", nonce)
	redir.URL.RawQuery = qry.Encode()

	http.Redirect(res, req, redir.URL.String(), http.StatusFound)
	return nil
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
func (g *Goic) Authenticate(name, code, nonce string, req *http.Request) (*Token, error) {
	p, _ := g.providers[name]

	tok, err := g.getToken(p, code, currentURL(req, false))
	if err != nil {
		return tok, err
	}

	if err := g.verifyToken(p, tok, nonce); err != nil {
		return tok, err
	}

	return tok, nil
}

// getToken actually gets token from Provider via wellKnown.TokenURI
func (g *Goic) getToken(p *Provider, code, redir string) (*Token, error) {
	tok := &Token{Provider: p.Name}
	buf, _ := json.Marshal(map[string]string{
		"grant_type":    "authorization_code",
		"code":          code,
		"redirect_uri":  redir,
		"client_id":     p.clientID,
		"client_secret": p.clientSecret,
	})

	req, err := http.NewRequest("POST", p.wellKnown.TokenURI, bytes.NewBuffer(buf))
	if err != nil {
		return tok, err
	}

	req.Header.Set("Content-Type", "application/json")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return tok, err
	}
	defer res.Body.Close()

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return tok, err
	}

	if err := json.Unmarshal(body, &tok); err != nil {
		return tok, err
	}

	if tok.Err != "" {
		msg := tok.Err
		if tok.ErrDesc != "" {
			msg += ": " + tok.ErrDesc
		}
		return tok, errors.New(msg)
	}

	if tok.IDToken == "" {
		return tok, ErrTokenEmpty
	}

	return tok, nil
}

// verifyToken checks and verifies authenticity and ownership of Token
func (g *Goic) verifyToken(p *Provider, tok *Token, nonce string) error {
	claims, err := verifyClaims(tok, nonce, p.clientID)
	if err != nil {
		return err
	}

	// todo: is this ok here?
	if p.wellKnown.KeysURI == "" {
		return nil
	}

	_, err = jwt.ParseWithClaims(tok.IDToken, claims, func(t *jwt.Token) (interface{}, error) {
		alg := t.Header["alg"].(string)
		if alg == "HS256" || alg == "HS384" || alg == "HS512" {
			return []byte(p.clientSecret), nil
		}

		if alg != "RS256" && alg != "RS384" && alg != "RS512" {
			return nil, ErrTokenAlgo
		}

		for _, key := range p.wellKnown.jwks.Keys {
			if (key.Kty == "RSA" && key.Kid == t.Header["kid"]) || (key.Alg == alg && key.Kid == t.Header["kid"]) {
				return &rsa.PublicKey{E: ParseExponent(key.E), N: ParseModulo(key.N)}, nil
			}
		}

		return nil, ErrTokenKey
	})

	return err
}

func verifyClaims(tok *Token, nonce, aud string) (jwt.Claims, error) {
	claims := jwt.MapClaims{}
	seg := strings.Split(tok.IDToken, ".")
	if len(seg) != 3 {
		return claims, ErrTokenInvalid
	}

	buf, _ := Base64UrlDecode(seg[1])
	if err := json.Unmarshal(buf, &claims); err != nil {
		return claims, ErrTokenClaims
	}

	usrNonce, ok := claims["nonce"]
	if ok && subtle.ConstantTimeCompare([]byte(nonce), []byte(usrNonce.(string))) == 0 {
		return claims, ErrTokenNonce
	}

	_, ok = claims["aud"]
	if ok && !claims.VerifyAudience(aud, true) {
		return claims, ErrTokenAud
	}

	return claims, nil
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
		http.Error(res, "Provider '"+name+"' not supported", http.StatusInternalServerError)
		return
	}

	qry := req.URL.Query()
	if msg := qry.Get("error"); msg != "" {
		if desc := qry.Get("error_description"); desc != "" {
			msg += ": " + desc
		}

		if g.verbose {
			log.Println("[err] goic request auth callback: " + msg)
		}
		http.Error(res, msg, http.StatusInternalServerError)
		return
	}

	code := qry.Get("code")
	if code == "" {
		if err := g.RequestAuth(name, res, req); err != nil {
			if g.verbose {
				log.Println("[err] goic request auth: %v\n", err)
			}
			http.Error(res, err.Error(), http.StatusInternalServerError)
		}
		return
	}

	nonce, err := g.checkState(qry.Get("state"))
	if err != nil {
		if g.verbose {
			log.Printf("[err] goic check state: %v\n", err)
		}
		http.Error(res, err.Error(), http.StatusInternalServerError)
		return
	}

	tok, err := g.Authenticate(name, code, nonce, req)
	if err != nil {
		if g.verbose {
			log.Printf("[err] goic request auth: %v\n", err)
		}
		http.Error(res, err.Error(), http.StatusInternalServerError)
		return
	}

	if g.userCallback == nil {
		res.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintln(res, "OK, the auth flow is complete. However, backend is yet to request userinfo")
		return
	}

	g.userCallback(tok, g.UserInfo(tok), res, req)
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
		return userErr(user, ErrProviderSupport)
	}

	if tok.AccessToken == "" {
		return userErr(user, ErrTokenAccessKey)
	}

	p := g.providers[tok.Provider]

	req, err := http.NewRequest("GET", p.wellKnown.UserInfoURI, nil)
	if err != nil {
		return userErr(user, err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+tok.AccessToken)

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return userErr(user, err)
	}
	defer res.Body.Close()

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return userErr(user, err)
	}

	if err := json.Unmarshal(body, &user); err != nil {
		return userErr(user, err)
	}

	return user
}
