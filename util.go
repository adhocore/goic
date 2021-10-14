package goic

import (
	"crypto/elliptic"
	"encoding/base64"
	"log"
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

// GetCurve gets the elliptic.Curve from last 3 chars of string s
func GetCurve(s string) elliptic.Curve {
	s3 := s[len(s)-3:]
	if s3 == "256" {
		return elliptic.P256()
	} else if s3 == "384" {
		return elliptic.P384()
	} else if s3 == "521" {
		return elliptic.P521()
	}
	return elliptic.P224()
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
			log.Printf("goic uncaught: %v\n", typ)
			msg = typ.Error()
		}

		http.Error(res, msg, http.StatusInternalServerError)
	}
}
