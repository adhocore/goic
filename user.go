package goic

import (
	"crypto/subtle"
	"encoding/json"
	"strings"

	"github.com/golang-jwt/jwt/v4"
)

// User represents user from well known user info endpoint
type User struct {
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified,omitempty"`
	FamilyName    string `json:"family_name,omitempty"`
	GivenName     string `json:"given_name,omitempty"`
	Locale        string `json:"locale,omitempty"`
	Name          string `json:"name"`
	Picture       string `json:"picture,omitempty"`
	Subject       string `json:"sub,omitempty"`
	Error         error  `json:"-"`
}

// Token represents token structure from well known token endpoint
type Token struct {
	Err          string `json:"error,omitempty"`
	ErrDesc      string `json:"error_description,omitempty"`
	IDToken      string `json:"id_token"`
	AccessToken  string `json:"access_token,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Provider     string `json:"provider,omitempty"`
}

// withError embeds Error to User
func (u *User) withError(err error) *User {
	u.Error = err
	return u
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
