package main

import (
	"log"
	"net/http"

	"github.com/adhocore/goic"
)

func facebook() {
	g := goic.New("/auth/o8", true)

	g.AddProvider(goic.Facebook.WithCredential("3462809713976120", "f6eab7509f137f45ff73d2fddf28604a"))

	g.UserCallback(func(t *goic.Token, u *goic.User, w http.ResponseWriter, r *http.Request) {
		log.Printf("token: %#v\n", t)
		log.Printf("user: %#v\n", u)
		_, _ = w.Write([]byte("All good, check backend console"))
	})

	handler := func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(r.Method + " " + r.URL.Path))
	}

	log.Println("Server running on https://localhost")
	log.Println("            Visit https://localhost/auth/o8/facebook")

	addr := "localhost:443"
	http.HandleFunc("/", g.MiddlewareFunc(handler))
	log.Fatal(http.ListenAndServeTLS(addr, "server.crt", "server.key", nil))
}
