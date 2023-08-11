package goic

import (
	"encoding/base64"
	"encoding/json"
	"log"
	"net/http"
	"net/url"
	"strings"
)

// Provider represents OpenID Connect provider
type Provider struct {
	wellKnown    *WellKnown
	QueryFn      func() string
	err          error
	Name         string
	URL          string
	Scope        string
	host         string
	clientID     string
	clientSecret string
	ResType      string
	Sandbox      bool
	discovered   bool
}

// WellKnown represents OpenID Connect well-known config
type WellKnown struct {
	Issuer      string   `json:"issuer"`
	KeysURI     string   `json:"jwks_uri"`
	AuthURI     string   `json:"authorization_endpoint"`
	TokenURI    string   `json:"token_endpoint"`
	UserInfoURI string   `json:"userinfo_endpoint"`
	SignOutURI  string   `json:"end_session_endpoint,omitempty"`
	RevokeURI   string   `json:"revocation_endpoint,omitempty"`
	XRevokeURI  string   `json:"token_revocation_endpoint,omitempty"`
	AlgoSupport []string `json:"id_token_signing_alg_values_supported"`
	jwks        struct {
		Keys []struct {
			Alg string `json:"alg"`
			Use string `json:"use,omitempty"`
			Kid string `json:"kid"`
			Kty string `json:"kty"`
			Crv string `json:"crv,omitempty"`
			E   string `json:"e,omitempty"`
			N   string `json:"n,omitempty"`
			X   string `json:"x,omitempty"`
			Y   string `json:"y,omitempty"`
		}
	}
}

// Microsoft is ready to use Provider instance
var Microsoft = &Provider{
	Name:  "microsoft",
	URL:   "https://login.microsoftonline.com/common/v2.0",
	Scope: "openid email profile offline_access",
}

// Google is ready to use Provider instance
var Google = &Provider{
	Name:  "google",
	URL:   "https://accounts.google.com",
	Scope: "openid email profile",
}

// Yahoo provider
var Yahoo = &Provider{
	Name:  "yahoo",
	URL:   "https://login.yahoo.com",
	Scope: "openid openid2 email profile",
}

// Paypal live provider
var Paypal = &Provider{
	Name:  "paypal",
	URL:   "https://www.paypalobjects.com",
	Scope: "openid email profile",
}

// PaypalSandbox provider
var PaypalSandbox = &Provider{
	Name:    "paypal",
	Sandbox: true,
	URL:     "https://www.paypalobjects.com",
	Scope:   "openid email profile",
}

var Facebook = &Provider{
	Name:      "facebook",
	ResType:   "code",
	URL:       "https://www.facebook.com",
	Scope:     "openid email public_profile",
	wellKnown: &WellKnown{TokenURI: "https://graph.facebook.com/v17.0/oauth/access_token"},
}

// WithCredential sets client id and secret for a Provider
func (p *Provider) WithCredential(id, secret string) *Provider {
	if id == "" || secret == "" {
		log.Fatalf("goic (%s): client ID and client secret may not be empty", p.Name)
	}

	p.clientID = id
	p.clientSecret = secret

	return p
}

// WithScope sets scope for a Provider
func (p *Provider) WithScope(s string) *Provider {
	if s == "" || !strings.Contains(s, "openid") {
		s = s + " openid"
	}
	p.Scope = strings.Trim(s, " ")

	return p
}

// SetQuery sets query func for inital auth request
func (p *Provider) SetQuery(fn func() string) *Provider {
	p.QueryFn = fn
	return p
}

// SetErr sets last encountered error
func (p *Provider) SetErr(err error) { p.err = err }

// Is checks if provider is given type
func (p *Provider) Is(name string) bool {
	return p.Name == name
}

// getWellKnown gets the well known config from Provider remote
func (p *Provider) getWellKnown() (*WellKnown, error) {
	if nil != p.wellKnown && p.discovered {
		return p.wellKnown, nil
	}

	// Fetch well-known config
	res, err := http.Get(strings.TrimSuffix(p.URL, "/") + "/.well-known/openid-configuration")
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	p.discovered = true
	if err := json.NewDecoder(res.Body).Decode(&p.wellKnown); err != nil {
		return nil, err
	}

	if p.wellKnown.RevokeURI == "" && p.wellKnown.XRevokeURI != "" {
		p.wellKnown.RevokeURI = p.wellKnown.XRevokeURI
	}

	if p.wellKnown.KeysURI == "" {
		return p.wellKnown, nil
	}

	// Fetch jwks keys
	res, err = http.Get(p.wellKnown.KeysURI)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	if err := json.NewDecoder(res.Body).Decode(&p.wellKnown.jwks); err != nil {
		return p.wellKnown, err
	}

	return p.wellKnown, nil
}

// GetURI gets an endpoint for given action
func (p *Provider) GetURI(action string) (uri string) {
	switch action {
	case "auth":
		uri = p.wellKnown.AuthURI
	case "token":
		uri = p.wellKnown.TokenURI
	case "userinfo":
		uri = p.wellKnown.UserInfoURI
	case "revoke":
		uri = p.wellKnown.RevokeURI
	case "signout":
		uri = p.wellKnown.SignOutURI
	}

	// if p.Sandbox && p.Is("paypal") {
	// 	uri = strings.Replace(uri, ".paypal.com", ".sandbox.paypal.com", 1)
	// }
	return uri
}

// CanRevoke checks if token can be revoked for this Provider
func (p *Provider) CanRevoke() bool {
	return p.wellKnown.RevokeURI != ""
}

// CanSignOut checks if token can be signed out for this Provider
func (p *Provider) CanSignOut() bool {
	return p.wellKnown.SignOutURI != ""
}

// AuthBasicHeader gives a string ready to use as Authorization header
// The returned value contains "Basic " prefix already
func (p *Provider) AuthBasicHeader() string {
	id := url.PathEscape(url.QueryEscape(p.clientID))
	pass := url.PathEscape(url.QueryEscape(p.clientSecret))

	return "Basic " + base64.StdEncoding.EncodeToString([]byte(id+":"+pass))
}
