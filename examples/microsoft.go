package main

import (
	"log"
	"net/http"
	"os"

	"github.com/adhocore/goic"
)

func microsoft() {
	// Init GOIC with a root uri and verbose mode (=true)
	g := goic.New("/auth/o8", true)

	// Register Microsoft provider with name microsoft and its auth URI
	// It will preemptively load well-known config and jwks keys
	p := g.NewProvider("microsoft", "https://login.microsoftonline.com/common/v2.0")

	// Configure credentials for Microsoft provider
	p.WithCredential(os.Getenv("MICROSOFT_CLIENT_ID"), os.Getenv("MICROSOFT_CLIENT_SECRET"))

	// Configure scope
	p.WithScope("openid email profile offline_access")

	// Define a callback that will receive token and user info on successful verification
	g.UserCallback(func(t *goic.Token, u *goic.User, w http.ResponseWriter, r *http.Request) {
		// Persist token and user info as you wish! Be sure to check for error in `u.Error` first
		// Use the available `w` and `r` params to show some nice page with message to your user
		// OR redirect them to homepage/dashboard etc

		// However, for the example, here I just dump it in backend console
		log.Println("token: ", t)
		log.Println("user: ", u)

		// and tell the user it is all good:
		_, _ = w.Write([]byte("All good, check backend console"))
	})

	// Listen address for server, 443 for https as OpenID connect mandates it!
	addr := "localhost:443"
	// You need to find a way to run your localhost in HTTPS as well.
	// You may also alias it something like `goic.lvh.me` (lvh is local virtual host)
	// *.lvh.me is automatically mapped to 127.0.0.1 in unix systems.

	// A catch-all dummy handler
	handler := func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(r.Method + " " + r.URL.Path))
	}

	log.Println("Server running on https://localhost")
	log.Println("            Visit https://localhost/auth/o8/microsoft")

	// This is just example (don't copy it)
	useMux := os.Getenv("GOIC_HTTP_MUX") == "1"
	if useMux {
		mux := http.NewServeMux()
		// If you use http mux, wrap your handler with g.MiddlewareHandler
		mux.Handle("/", g.MiddlewareHandler(http.HandlerFunc(handler)))
		server := &http.Server{Addr: addr, Handler: mux}
		log.Fatal(server.ListenAndServeTLS("server.crt", "server.key"))
	} else {
		// If you just use plain simple handler func,
		// wrap your handler with g.MiddlewareFunc
		http.HandleFunc("/", g.MiddlewareFunc(handler))
		log.Fatal(http.ListenAndServeTLS(addr, "server.crt", "server.key", nil))
	}
}
