package main

import (
	"log"
	"net/http"
	"os"

	"github.com/adhocore/goic"
)

func main() {
	g := goic.New("/auth/o8", true)
	g.AddProvider(goic.Google.WithCredential(os.Getenv("GOOGLE_CLIENT_ID"), os.Getenv("GOOGLE_CLIENT_SECRET")))
	g.AddProvider(goic.Microsoft.WithCredential(os.Getenv("MICROSOFT_CLIENT_ID"), os.Getenv("MICROSOFT_CLIENT_SECRET")))

	g.UserCallback(func(t *goic.Token, u *goic.User, w http.ResponseWriter, r *http.Request) {
		log.Println("token: ", t)
		log.Println("user: ", u)
		_, _ = w.Write([]byte("All good, check backend console"))
	})

	addr := "localhost:443"
	handler := func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(r.Method + " " + r.URL.Path))
	}

	log.Println("Server running on https://localhost")
	log.Println("            Visit https://localhost/auth/o8/google")
	log.Println("               OR https://localhost/auth/o8/microsoft")
	http.HandleFunc("/", g.MiddlewareFunc(handler))
	log.Fatal(http.ListenAndServeTLS(addr, "server.crt", "server.key", nil))
}
