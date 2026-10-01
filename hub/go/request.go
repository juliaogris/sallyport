package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// request is one request to the Durable Object. Header names are lower
// case, and repeated headers are joined with ", ", as the Workers runtime
// gives them.
type request struct {
	method, host, path, query string
	header                    map[string]string
	body                      []byte
}

// response is what the Durable Object answers. At most one of body,
// stream and ws is set.
type response struct {
	status int
	header [][2]string
	body   string
	stream *bodyStream
	ws     *wsConn
	// manual sends the body as is, for a body that is already encoded.
	manual bool
	// raw sends body as bytes, so the runtime adds no Content-Type.
	raw bool
}

func (r *response) add(name, value string) *response {
	r.header = append(r.header, [2]string{name, value})
	return r
}

// textError is the Rust hub's `Response::error`: the message as a body
// with no Content-Type.
func textError(msg string, status int) *response {
	return &response{status: status, body: msg, raw: true}
}

func html(body string) *response {
	return (&response{status: 200, body: body}).add("content-type", "text/html; charset=utf-8")
}

func jsonResponse(v any) *response {
	b, err := json.Marshal(v)
	if err != nil {
		return textError(err.Error(), 500)
	}
	return (&response{status: 200, body: string(b)}).add("content-type", "application/json")
}

// redirect returns a 303 to location.
func redirect(location string) *response {
	return (&response{status: 303}).add("location", location)
}

// cookie returns the value of the named cookie, and whether it is there.
func (r *request) cookie(name string) (string, bool) {
	for _, c := range strings.Split(r.header["cookie"], ";") {
		k, v, ok := strings.Cut(strings.TrimSpace(c), "=")
		if ok && k == name {
			return v, true
		}
	}
	return "", false
}

func setCookie(name, value string) string {
	return name + "=" + value + "; Path=/; Secure; HttpOnly; SameSite=Lax"
}

func expireCookie(name string) string {
	return name + "=; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=0"
}

// sameOrigin reports whether the Origin header is https://host.
func (r *request) sameOrigin(host string) bool {
	o, ok := r.header["origin"]
	return ok && o == "https://"+host
}

// sameOriginFetch returns false when the browser says the request came
// from another origin. A request with neither Sec-Fetch-Site nor Origin is
// not from a browser page and passes.
func (r *request) sameOriginFetch(host string) bool {
	if site, ok := r.header["sec-fetch-site"]; ok {
		return site == "same-origin" || site == "none"
	}
	if o, ok := r.header["origin"]; ok {
		return o == "https://"+host
	}
	return true
}

// ctEq compares two strings in time that depends only on their lengths.
func ctEq(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	var v byte
	for i := 0; i < len(a); i++ {
		v |= a[i] ^ b[i]
	}
	return v == 0
}

// checkAssertion returns an error unless a is a JSON object with an id
// and the type "public-key", as a WebAuthn assertion has.
func checkAssertion(a []byte) error {
	var v struct {
		ID   string `json:"id"`
		Type string `json:"type"`
	}
	if err := json.Unmarshal(a, &v); err != nil {
		return fmt.Errorf("assertion: %w", err)
	}
	if v.ID == "" || v.Type != "public-key" {
		return errors.New("assertion: not a public-key credential")
	}
	return nil
}
