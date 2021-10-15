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

	g.UserCallback(func(t *goic.Token, u *goic.User, w http.ResponseWriter, r *http.Request) {
		log.Printf("token: %v\nuser: %v\n", t, u)
		uri := "https://localhost/auth/signout?p=" + t.Provider + "&t=" + t.AccessToken
		uri = fmt.Sprintf(`, click <a href="%s">here</a> to signout (some provider may not support it)`, uri)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte("All good, check backend console" + uri))
	})

	addr := "localhost:443"
	handler := func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(r.Method + " " + r.URL.Path))
	}

	log.Println("Server running on https://localhost, You can visit any of the below URLs:")
	for _, v := range []string{"google", "microsoft", "yahoo"} {
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

	log.Fatal(http.ListenAndServeTLS(addr, "server.crt", "server.key", nil))
}
