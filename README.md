# adhocore/goic

[![Latest Version](https://img.shields.io/github/release/adhocore/gronx.svg?style=flat-square)](https://github.com/adhocore/goic/releases)
[![Software License](https://img.shields.io/badge/license-MIT-brightgreen.svg?style=flat-square)](LICENSE)
[![Go Report](https://goreportcard.com/badge/github.com/adhocore/goic)](https://goreportcard.com/report/github.com/adhocore/goic)
[![Donate 15](https://img.shields.io/badge/donate-paypal-blue.svg?style=flat-square&label=donate+15)](https://www.paypal.me/ji10/15usd)
[![Donate 25](https://img.shields.io/badge/donate-paypal-blue.svg?style=flat-square&label=donate+25)](https://www.paypal.me/ji10/25usd)
[![Donate 50](https://img.shields.io/badge/donate-paypal-blue.svg?style=flat-square&label=donate+50)](https://www.paypal.me/ji10/50usd)
[![Tweet](https://img.shields.io/twitter/url/http/shields.io.svg?style=social)](https://twitter.com/intent/tweet?text=Simple+Golang+OpenID+Connect+client&url=https://github.com/adhocore/goic&hashtags=go,golang,openid,oauth,openid-connect,connect,oauth2)

GOIC, **Go Open ID Connect**, is OpenID connect client library for Golang.
It supports the *Authorization Code Flow* of OpenID Connect specification.
It doesn't yet support `refresh_token` grant type and that will be added later.

It is a weekend hack project and is work in progress and not production ready yet.

# Installation

```sh
go get github.com/adhocore/goic
```

# Usage

Decide an endpoint (aka URI) in your server where you would like `goic` to intercept and add OpenID Connect flow.
Let's say `/auth/o8`. Then the provider name follows it.
All the OpenID providers that your server should support will need a unique name and each of the
providers get a URI like so `/auth/o8/<name>`. Example:

| Provider | Name | OpenID URI | Demo URL |
|----------|------|------------|----------|
| Google | google | `/auth/o8/google` | [urlssh.xyz/auth/o8/google](https://urlssh.xyz/auth/o8/google) |
| Microsoft | microsoft | `/auth/o8/microsoft` | [urlssh.xyz/auth/o8/microsoft](https://urlssh.xyz/auth/o8/microsoft) |
| Yahoo | yahoo | `/auth/o8/yahoo` | [urlssh.xyz/auth/o8/yahoo](https://urlssh.xyz/auth/o8/yahoo) |

> On successful verification your information is [echoed back](https://github.com/adhocore/urlsh/blob/main/router/router.go#L48-L53) to you as JSON but **not** saved in server (pinky promise).

**Important:** All the providers **must** provide .well-known configurations for OpenID auto discovery.

Get ready with OpenID provider credentials (client id and secret).
For Google, check [this](https://developers.google.com/identity/gsi/web/guides/get-google-api-clientid).
To use the example below you need to export `GOOGLE_CLIENT_ID` and `GOOGLE_CLIENT_SECRET` env vars.

You also need to configure application domain and redirect URI in the Provider console/dashboard.
(redirect URI is same as OpenID URI in above table).

Below is an example for authorization code flow but instead of copy/pasting it entirely you can use it for reference.

```go
package main

import (
	"log"
	"net/http"
	"os"

	"github.com/adhocore/goic"
)

func main() {
	// Init GOIC with a root uri and verbose mode (=true)
	g := goic.New("/auth/o8", true)

	// Register Google provider with name google and its auth URI
	// It will preemptively load well-known config and jwks keys
	p := g.NewProvider("google", "https://accounts.google.com")

	// Configure credentials for Google provider
	p.WithCredential(os.Getenv("GOOGLE_CLIENT_ID"), os.Getenv("GOOGLE_CLIENT_SECRET"))

	// Configure scope
	p.WithScope("openid email profile")

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
	log.Println("            Visit https://localhost/auth/o8/google")

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
```

```go
// OR, you can use shorthand syntax to register providers:

g := goic.New("/auth/o8", false)
g.AddProvider(goic.Google.WithCredential(os.Getenv("GOOGLE_CLIENT_ID"), os.Getenv("GOOGLE_CLIENT_SECRET")))
g.AddProvider(goic.Microsoft.WithCredential(os.Getenv("MICROSOFT_CLIENT_ID"), os.Getenv("MICROSOFT_CLIENT_SECRET")))
g.AddProvider(goic.Yahoo.WithCredential(os.Getenv("YAHOO_CLIENT_ID"), os.Getenv("YAHOO_CLIENT_SECRET")))

// ...
```

After having code like that, build the binary (`go build`) and run server program (`./<binary>`).

You need to point `Sign in with <provider>`  button to `https://localhost/auth/o8/<provider>` for your end user.
For example:
```html
<a href="https://localhost/auth/o8/google">Sign in with Google</a>
<a href="https://localhost/auth/o8/microsoft">Sign in with Microsoft</a>
<a href="https://localhost/auth/o8/yahoo">Sign in with Yahoo</a>
```

The complete flow is managed and handled by GOIC for you and on successful verification,
You will be able to receive user and token info in your callback via `g.UserCallback`!
That is where you persist the user data, set some cookie etc.

Check [examples](./examples) directory later for more, as it will be updated
when GOIC has new features.

> The example and discussion here assume `localhost` domain so adjust that accordingly for your domains.

---
## GOIC API

GOIC supports full end-to-end for Authorization Code Flow, however if you want to manually interact, here's summary of API:

#### Check Provider

```go
g := goic.New("/auth/o8", false)
g.NewProvider("abc", "...").WithCredential("...", "...")

g.Supports("abc") // true
g.Supports("xyz") // false
```

#### Refresh Token

Use it to request Access token by using refresh token.

```go
g := goic.New("/auth/o8", false)
t := &goic.Token{RefreshToken: "your refresh token", Provider: goic.Microsoft.Name}
tok, err := g.RefreshToken(t)
// Do something with tok.AccessToken
```

#### Auth Request

Manually request authentication from OpenID Provider.

```go
g := goic.New("/auth/o8", false)
p := g.NewProvider("abc", "...").WithCredential("...", "...")

// Generate random unique state and nonce
state, nonce := goic.RandomString(24), goic.RandomString(24)
// You must save them to cookie/session, so it can be retrieved later for crosscheck

// redir is the redirect url in your host for provider of interest
redir := "https://localhost/auth/o8/" + p.Name

// Redirects to provider first and then back to above redir url
// res = http.ResponseWriter, req = *http.Request
err := g.RequestAuth(p, state, nonce, redir, res, req)
```

#### Authentication

Manually attempt to authenticate after the request comes back from OpenID Provider.

```go
g := goic.New("/auth/o8", false)
p := g.NewProvider("abc", "...").WithCredential("...", "...")

// Read openid provider code from query param, and nonce from cookie/session etc
// PS: Validate that the nonce is relevant to the state sent by openid provider
code, nonce := "", ""

// redir is the redirect url in your host for provider of interest
redir := "https://localhost/auth/o8/" + p.Name

tok, err := g.Authenticate(p, code, nonce, redir)
```

### Userinfo

Manually request Userinfo by using the token returned by Authentication above.
```go
g := goic.New("/auth/o8", false)
p := g.NewProvider("abc", "...").WithCredential("...", "...")
// ...
tok, err := g.Authenticate(p, code, nonce, redir)
user := g.UserInfo(tok)
err := user.Error
```

---
### Demo

`GOIC` has been implemented in opensource project [adhocore/urlsh](https://github.com/adhocore/urlsh):

| Provider | Name | Demo URL |
|----------|------|------------|
| Google | google | [urlssh.xyz/auth/o8/google](https://urlssh.xyz/auth/o8/google) |
| Microsoft | microsoft | [urlssh.xyz/auth/o8/microsoft](https://urlssh.xyz/auth/o8/microsoft) |
| Yahoo | yahoo | [urlssh.xyz/auth/o8/yahoo](https://urlssh.xyz/auth/o8/yahoo) |

On successful verification your information is [echoed back](https://github.com/adhocore/urlsh/blob/main/router/router.go#L48-L53) to you as JSON but **not** saved in server (pinky promise).

---
# TODO

- Support refresh token grant_type
- Tests and more tests
- Release stable version
- ~~Support OpenID `Implicit Flow`~~ [Check #3](https://github.com/adhocore/goic/issues/3)

## License

> &copy; [MIT](./LICENSE) | 2021-2099, Jitendra Adhikari

## Credits

Release managed by [please](https://github.com/adhocore/please).

---
### Other projects
My other golang projects you might find interesting and useful:

- [**gronx**](https://github.com/adhocore/gronx) - Lightweight, fast and dependency-free Cron expression parser (due checker), task scheduler and/or daemon for Golang (tested on v1.13 and above) and standalone usage.
- [**urlsh**](https://github.com/adhocore/urlsh) - URL shortener and bookmarker service with UI, API, Cache, Hits Counter and forwarder using postgres and redis in backend, bulma in frontend; has [web](https://urlssh.xyz) and cli client
- [**fast**](https://github.com/adhocore/fast) - Check your internet speed with ease and comfort right from the terminal
