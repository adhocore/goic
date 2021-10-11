package goic

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"
)

type Provider struct {
	Name         string
	URL          string
	Scope        string
	host         string
	clientID     string
	clientSecret string
	wellKnown    *WellKnown
}

type WellKnown struct {
	Issuer      string   `json:"issuer"`
	KeysURI     string   `json:"jwks_uri"`
	AuthURI     string   `json:"authorization_endpoint"`
	TokenURI    string   `json:"token_endpoint"`
	UserInfoURI string   `json:"userinfo_endpoint"`
	AlgoSupport []string `json:"id_token_signing_alg_values_supported"`
	jwks        struct {
		Keys []struct {
			Alg string `json:"alg"`
			Use string `json:"use"`
			Kid string `json:"kid"`
			Kty string `json:"kty"`
			E   string `json:"e"`
			N   string `json:"n"`
		}
	}
}

func (p *Provider) WithCredential(id string, secret string) *Provider {
	if id == "" || secret == "" {
		log.Fatalf("goic (%s): client ID and client secret may not be empty", p.Name)
	}

	p.clientID = id
	p.clientSecret = secret

	return p
}

func (p *Provider) WithScope(s string) *Provider {
	if s == "" || !strings.Contains(s, "openid") {
		s = s + " openid"
	}
	p.Scope = strings.Trim(s, " ")

	return p
}

func (p *Provider) getWellKnown() (*WellKnown, error) {
	if nil != p.wellKnown {
		return p.wellKnown, nil
	}

	// Fetch well-known config
	res, err := http.Get(strings.TrimSuffix(p.URL, "/") + "/.well-known/openid-configuration")
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	if err := json.NewDecoder(res.Body).Decode(&p.wellKnown); err != nil {
		return nil, err
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
