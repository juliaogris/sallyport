package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"
)

// request is one request to the Durable Object. Header names are lower
// case, and repeated headers are joined with ", ", as the Workers runtime
// gives them.
type request struct {
	method, host, path, query string
	header                    map[string]string
	body                      []byte
	// bodyReader is the body of an app request, which Go reads as it
	// arrives, or nil. Only one of body and bodyReader is set. serve closes
	// it once the request is answered, unless bodyTaken is true, and then
	// the transport that took it closes it, at the latest when the
	// response closes.
	bodyReader io.ReadCloser
	bodyTaken  bool
}

// response is what the Durable Object answers. At most one of body,
// stream, ws and browser is set.
type response struct {
	status int
	header [][2]string
	body   string
	stream *bodyStream
	ws     *wsConn
	// browser is the browser's end of a WebSocket to an app.
	browser *browserWS
	// manual sends the body as is, for a body that is already encoded.
	manual bool
	// raw sends body as bytes, so the runtime adds no Content-Type.
	raw bool
}

func (r *response) add(name, value string) *response {
	r.header = append(r.header, [2]string{name, value})
	return r
}

// textError returns the message as a body with no Content-Type.
func textError(msg string, status int) *response {
	return &response{status: status, body: msg, raw: true}
}

// html returns a hub page. No other page may frame it, so that a page on
// another host, such as an app host under the login host, cannot put the
// hub's buttons or passkey prompts under its own.
func html(body string) *response {
	return (&response{status: 200, body: body}).
		add("content-type", "text/html; charset=utf-8").
		add("content-security-policy", "frame-ancestors 'none'").
		add("x-frame-options", "DENY")
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

// queryValue returns the first value of the query parameter name, and
// whether the query has it. A parameter with no value is present.
func (r *request) queryValue(name string) (string, bool) {
	q, err := url.ParseQuery(strings.TrimPrefix(r.query, "?"))
	if err != nil || !q.Has(name) {
		return "", false
	}
	return q.Get(name), true
}

// fromSameSite reports whether the browser says the request came from a
// page on the same site and is not a prefetch. A request without
// Sec-Fetch-Site is refused.
func (r *request) fromSameSite() bool {
	_, prefetch := r.header["sec-purpose"]
	site := r.header["sec-fetch-site"]
	return (site == "same-origin" || site == "same-site") && !prefetch
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
// and the type "public-key", as a WebAuthn assertion has, and its client
// data is from a page at origin, as checkClientData checks.
func checkAssertion(a []byte, origin string) error {
	var v struct {
		ID       string `json:"id"`
		Type     string `json:"type"`
		Response struct {
			ClientDataJSON string `json:"clientDataJSON"`
		} `json:"response"`
	}
	if err := json.Unmarshal(a, &v); err != nil {
		return fmt.Errorf("assertion: %w", err)
	}
	if v.ID == "" || v.Type != "public-key" {
		return errors.New("assertion: not a public-key credential")
	}
	return checkClientData(v.Response.ClientDataJSON, "webauthn.get", origin)
}

// checkClientData returns an error unless clientDataJSON, in base64url
// without padding, is the client data of a WebAuthn call of type typ, made
// by a page at origin and not in a frame from another origin.
func checkClientData(clientDataJSON, typ, origin string) error {
	b, err := base64.RawURLEncoding.DecodeString(clientDataJSON)
	if err != nil {
		return fmt.Errorf("client data: %w", err)
	}
	var v struct {
		Type        string `json:"type"`
		Origin      string `json:"origin"`
		CrossOrigin bool   `json:"crossOrigin"`
	}
	if err := json.Unmarshal(b, &v); err != nil {
		return fmt.Errorf("client data: %w", err)
	}
	// Auth accepts a page on any host under the relying party ID, and an app
	// in SUB_APPS is on such a host, so only the hub checks that the answer
	// is from its own page.
	switch {
	case v.Type != typ:
		return fmt.Errorf("client data: type %q, want %q", v.Type, typ)
	case v.Origin != origin:
		return fmt.Errorf("client data: origin %q, want %q", v.Origin, origin)
	case v.CrossOrigin:
		return errors.New("client data: from a frame on another origin")
	}
	return nil
}
