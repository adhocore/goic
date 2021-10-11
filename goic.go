package goic

import (
	"bytes"
	"crypto/rsa"
	"crypto/subtle"
	"encoding/base64"
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
	ErrProviderState   = errors.New("goic provider: invalid request state")
	ErrProviderSupport = errors.New("goic provider: unsupported provider")
	ErrTokenEmpty      = errors.New("goic id_token: empty token")
	ErrTokenInvalid    = errors.New("goic id_token: invalid id_token")
	ErrTokenNonce      = errors.New("goic id_token: invalid nonce")
	ErrTokenAud        = errors.New("goic id_token: invalid audience")
	ErrTokenAlgo       = errors.New("goic id_token: unsupported signing algo")
	ErrTokenKey        = errors.New("goic id_token: can't determine signing key")
	ErrTokenAccessKey  = errors.New("goic id_token: invalid access_token")
)

var (
	stateLength = 16
	nonceLength = 20
)

type UserCallback func(t *Token, u *User, w http.ResponseWriter, r *http.Request)

type Goic struct {
	URIPrefix    string
	verbose      bool
	providers    map[string]*Provider
	userCallback UserCallback
	sLock        sync.RWMutex
	states       map[string]string
}

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

func New(uri string, verbose bool) *Goic {
	providers := make(map[string]*Provider)
	states := make(map[string]string)

	return &Goic{URIPrefix: uri, verbose: verbose, providers: providers, states: states}
}

func (g *Goic) NewProvider(name string, uri string) *Provider {
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

func (g *Goic) Supports(name string) bool {
	_, ok := g.providers[name]
	return ok
}

func (g *Goic) currentURL(req *http.Request, query bool) string {
	u := req.URL
	if u.Scheme == "" {
		u.Scheme = "https"
	}
	if u.Host == "" {
		u.Host = req.Header.Get("Host")
		if u.Host == "" {
			u.Host = req.Host
		}
	}
	if !query {
		return strings.Replace(u.String(), "?"+u.RawQuery, "", 1)
	}

	return u.String()
}

func (g *Goic) RequestAuth(name string, res http.ResponseWriter, req *http.Request) error {
	p := g.providers[name]

	redir, err := http.NewRequest("GET", p.wellKnown.AuthURI, nil)
	if err != nil {
		return err
	}

	qry := redir.URL.Query()
	qry.Add("response_type", "code")
	qry.Add("redirect_uri", g.currentURL(req, false))
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

func (g *Goic) Authenticate(name string, code string, nonce string, req *http.Request) (*Token, error) {
	p, _ := g.providers[name]

	tok, err := g.getToken(p, code, g.currentURL(req, false))
	if err != nil {
		return tok, err
	}

	if err := g.verifyToken(p, tok, nonce); err != nil {
		return tok, err
	}

	return tok, nil
}

func (g *Goic) getToken(p *Provider, code string, redir string) (*Token, error) {
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

func (g *Goic) verifyToken(p *Provider, tok *Token, nonce string) error {
	if p.wellKnown.KeysURI == "" {
		return nil
	}
	seg := strings.Split(tok.IDToken, ".")
	if len(seg) != 3 {
		return ErrTokenInvalid
	}

	claims := jwt.MapClaims{}
	str, _ := base64.StdEncoding.DecodeString(seg[1])
	_ = json.Unmarshal(str, &claims)

	if subtle.ConstantTimeCompare([]byte(nonce), []byte(claims["nonce"].(string))) == 0 {
		return ErrTokenNonce
	}

	if !claims.VerifyAudience(p.clientID, true) {
		return ErrTokenAud
	}

	_, err := jwt.ParseWithClaims(tok.IDToken, claims, func(t *jwt.Token) (interface{}, error) {
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

func (g *Goic) MiddlewareHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
		if strings.Index(req.URL.Path, g.URIPrefix) != 0 {
			next.ServeHTTP(res, req)
		} else {
			g.process(res, req)
		}
	})
}

func (g *Goic) MiddlewareFunc(next http.HandlerFunc) http.HandlerFunc {
	return func(res http.ResponseWriter, req *http.Request) {
		if strings.Index(req.URL.Path, g.URIPrefix) != 0 {
			next(res, req)
		} else {
			g.process(res, req)
		}
	}
}

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
			log.Println(msg)
		}
		http.Error(res, msg, http.StatusInternalServerError)
		return
	}

	code := qry.Get("code")
	if code == "" {
		if err := g.RequestAuth(name, res, req); err != nil {
			if g.verbose {
				log.Printf("%v\n", err)
			}
			http.Error(res, err.Error(), http.StatusInternalServerError)
		}
		return
	}

	nonce, err := g.checkState(qry.Get("state"))
	if err != nil {
		if g.verbose {
			log.Printf("%v\n", err)
		}
		http.Error(res, err.Error(), http.StatusInternalServerError)
		return
	}

	tok, err := g.Authenticate(name, code, nonce, req)
	if err != nil {
		if g.verbose {
			log.Printf("%v\n", err)
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

func (g *Goic) UserCallback(cb UserCallback) *Goic {
	g.userCallback = cb
	return g
}

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
