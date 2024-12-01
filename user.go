package goic

import (
	"crypto/subtle"
	"encoding/json"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

// User represents user from well known user info endpoint
type User struct {
	Error         error  `json:"-"`
	Email         string `json:"email"`
	FamilyName    string `json:"family_name,omitempty"`
	GivenName     string `json:"given_name,omitempty"`
	Locale        string `json:"locale,omitempty"`
	Name          string `json:"name"`
	Picture       string `json:"picture,omitempty"`
	Subject       string `json:"sub,omitempty"`
	EmailVerified bool   `json:"email_verified,omitempty"`
}

// withError embeds Error to User
func (u *User) withError(err error) *User {
	u.Error = err
	return u
}

func (u *User) FromClaims(c jwt.MapClaims) *User {
	u.Name = c["name"].(string)
	u.GivenName = c["given_name"].(string)
	u.FamilyName = c["family_name"].(string)
	u.Email = c["email"].(string)
	u.Picture = c["picture"].(string)
	u.Subject = c["sub"].(string)
	return u
}

// Token represents token structure from well known token endpoint
type Token struct {
	Claims       jwt.MapClaims `json:"-"`
	Err          string        `json:"error,omitempty"`
	ErrDesc      string        `json:"error_description,omitempty"`
	IDToken      string        `json:"id_token"`
	AccessToken  string        `json:"access_token,omitempty"`
	RefreshToken string        `json:"refresh_token,omitempty"`
	Provider     string        `json:"provider,omitempty"`
}

// verifyClaims verifies the claims of a Token
func (tok *Token) VerifyClaims(nonce, aud string) (err error) {
	claims := jwt.MapClaims{}
	tok.Claims = jwt.MapClaims{}

	seg := strings.Split(tok.IDToken, ".")
	if len(seg) != 3 {
		return ErrTokenInvalid
	}

	buf, _ := Base64UrlDecode(seg[1])
	if err := json.Unmarshal(buf, &claims); err != nil {
		return ErrTokenClaims
	}

	usrNonce, ok := claims["nonce"]
	if ok && subtle.ConstantTimeCompare([]byte(nonce), []byte(usrNonce.(string))) == 0 {
		return ErrTokenNonce
	}

	if err = jwt.NewValidator().Validate(claims); err != nil {
		return err
	}

	tok.Claims = claims // attach only if valid
	return nil
}
