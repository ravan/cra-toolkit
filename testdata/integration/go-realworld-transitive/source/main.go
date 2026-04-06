package main

import (
	"fmt"
	"net/http"

	"golang.org/x/net/http2"
)

func handler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Hello, %s", r.URL.Path)
}

func main() {
	srv := &http.Server{Addr: ":8443", Handler: http.HandlerFunc(handler)}
	if err := http2.ConfigureServer(srv, nil); err != nil {
		fmt.Printf("h2 config error: %v\n", err)
	}
	if err := srv.ListenAndServeTLS("cert.pem", "key.pem"); err != nil {
		fmt.Printf("server error: %v\n", err)
	}
}
