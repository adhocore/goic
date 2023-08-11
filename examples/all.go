package main

import (
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/adhocore/goic"
)

func main() {
	g := goic.New("/auth/o8", true)
	g.AddProvider(goic.Google.WithCredential(os.Getenv("GOOGLE_CLIENT_ID"), os.Getenv("GOOGLE_CLIENT_SECRET")))
	g.AddProvider(goic.Microsoft.WithCredential(os.Getenv("MICROSOFT_CLIENT_ID"), os.Getenv("MICROSOFT_CLIENT_SECRET")))
	g.AddProvider(goic.Yahoo.WithCredential(os.Getenv("YAHOO_CLIENT_ID"), os.Getenv("YAHOO_CLIENT_SECRET")))
	g.AddProvider(goic.Paypal.WithCredential(os.Getenv("PAYPAL_CLIENT_ID"), os.Getenv("PAYPAL_CLIENT_SECRET")))
	g.AddProvider(goic.Facebook.WithCredential(os.Getenv("FACEBOOK_CLIENT_ID"), os.Getenv("FACEBOOK_CLIENT_SECRET")))

	g.UserCallback(func(t *goic.Token, u *goic.User, w http.ResponseWriter, r *http.Request) {
		log.Printf("token: %v\nuser: %v\n", t, u)
		uri1 := "https://localhost/auth/signout?p=" + t.Provider + "&t=" + t.AccessToken
		uri1 = fmt.Sprintf(`,<br><br>click <a href="%s" target="_blank">here</a> to signout (some provider may not support it)`, uri1)
		uri2 := "https://localhost/auth/revoke?p=" + t.Provider + "&t=" + t.AccessToken
		uri2 = fmt.Sprintf(`,<br><br>click <a href="%s" target="_blank">here</a> to revoke (some provider may not support it)`, uri2)

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte("All good, check backend console" + uri1 + uri2))
	})

	addr := "localhost:443"
	handler := func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(r.Method + " " + r.URL.Path))
	}

	log.Println("Server running on https://localhost, You can visit any of the below URLs:")
	for _, v := range []string{"google", "facebook", "microsoft", "yahoo", "paypal"} {
		log.Printf("  https://localhost/auth/o8/%s\n", v)
	}
	http.HandleFunc("/", g.MiddlewareFunc(handler))

	// SignOut handler
	http.HandleFunc("/auth/signout/", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		tok := &goic.Token{Provider: q.Get("p"), AccessToken: q.Get("t")}
		if err := g.SignOut(tok, "", w, r); err != nil {
			http.Error(w, "can't signout: "+err.Error(), http.StatusInternalServerError)
		}
	})

	// Revoke Handler
	http.HandleFunc("/auth/revoke/", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		tok := &goic.Token{Provider: q.Get("p"), AccessToken: q.Get("t")}
		if err := g.RevokeToken(tok); err != nil {
			http.Error(w, "Can't revoke: "+err.Error(), http.StatusInternalServerError)
			return
		}
		_, _ = w.Write([]byte("Revoked token successfully"))
	})

	log.Fatal(http.ListenAndServeTLS(addr, "server.crt", "server.key", nil))
}
