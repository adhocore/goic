package goic

import (
	"encoding/base64"
	"math/big"
	"math/rand"
	"net/http"
	"strings"
	"time"
)

var (
	randomPool  = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	poolLength  = len(randomPool)
	urlDecodeRe = strings.NewReplacer("-", "+", "_", "/")
)

// RandomString generates random string of given length
// It sets rand seed on each call and returns generated string.
func RandomString(len int) string {
	str := make([]byte, len)
	rand.Seed(time.Now().UTC().UnixNano())

	for i := range str {
		str[i] = randomPool[rand.Intn(poolLength)]
	}

	return string(str)
}

// Base64UrlDecode decodes JWT segments with base64 accounting for URL chars
func Base64UrlDecode(s string) ([]byte, error) {
	pad := len(s) % 4
	for pad > 0 {
		s += "="
		pad--
	}

	return base64.StdEncoding.DecodeString(urlDecodeRe.Replace(s))
}

// ParseModulo parses the "n" value of jwks key
func ParseModulo(ns string) *big.Int {
	buf, _ := Base64UrlDecode(ns)
	return new(big.Int).SetBytes(buf)
}

// ParseExponent ParseModulo parses the "e" value of jwks key
func ParseExponent(es string) int {
	if es == "AQAB" {
		return 65537
	}

	buf, _ := Base64UrlDecode(es)
	return int(new(big.Int).SetBytes(buf).Uint64())
}

// currentURL gets the current request URL with/without query
func currentURL(req *http.Request, query bool) string {
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

// trapError recovers panics during OpenID operation
func trapError(res http.ResponseWriter) {
	msg := "Something went wrong"
	if rec := recover(); rec != nil {
		switch typ := rec.(type) {
		case error:
			msg = typ.Error()
		}

		http.Error(res, msg, http.StatusInternalServerError)
	}
}

// userError embeds error to User
func userErr(u *User, err error) *User {
	u.Error = err
	return u
}
