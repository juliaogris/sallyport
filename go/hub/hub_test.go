package main

import (
	"encoding/json"
	"os"
	"testing"
)

func TestClassify(t *testing.T) {
	c := &config{owner: "go", domain: "example.com"}
	tests := []struct {
		host string
		kind hostKind
		app  string
	}{
		{"go.example.com", hostLogin, ""},
		{"bench-go.example.com", hostApp, "bench"},
		{"octocam-go.example.com", hostApp, "octocam"},
		{"Bench-go.example.com", hostNone, ""},
		{"-go.example.com", hostNone, ""},
		{"a-b-go.example.com", hostNone, ""},
		{"rust.example.com", hostNone, ""},
		{"go.example.com.evil", hostNone, ""},
		{"x.go.example.com", hostNone, ""},
	}
	for _, tt := range tests {
		kind, app := c.classify(tt.host)
		if kind != tt.kind || app != tt.app {
			t.Errorf("classify(%q) = %v, %q, want %v, %q", tt.host, kind, app, tt.kind, tt.app)
		}
	}
}

func TestParseApps(t *testing.T) {
	got := parseApps("bench, cam:/stream,Bad,octo:relative,x://y,octocam:/stream")
	want := []app{{"bench", "/"}, {"cam", "/stream"}, {"octocam", "/stream"}}
	if len(got) != len(want) {
		t.Fatalf("parseApps = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("parseApps[%d] = %v, want %v", i, got[i], want[i])
		}
	}
}

func TestProtoRoundTrip(t *testing.T) {
	msg := changeUserAuthenticationRequest("tok", "public-key", []byte{1, 2}, []byte("cd"), []byte("att"))
	f, err := decode(msg)
	if err != nil {
		t.Fatal(err)
	}
	cred := f.msg(3).msg(3)
	if f.str(1) != "tok" || f.str(4) != "passkey" || cred.str(1) != "public-key" || string(cred.msg(3).bytes(2)) != "att" {
		t.Errorf("decoded %v", f)
	}
	// An empty optional message is still sent, as prost sends it.
	if got := passwordlessChallengeRequest(); string(got) != "\x22\x00\x32\x02\x08\x02" {
		t.Errorf("passwordless request = %x", got)
	}
}

func TestCookies(t *testing.T) {
	r := &request{header: map[string]string{"cookie": "a=1; __Host-sp_app=sid; b=2"}}
	if v, ok := r.cookie("__Host-sp_app"); !ok || v != "sid" {
		t.Errorf("cookie = %q, %v", v, ok)
	}
	if _, ok := r.cookie("c"); ok {
		t.Error("cookie c found")
	}
	if !ctEq("abc", "abc") || ctEq("abc", "abd") || ctEq("abc", "ab") {
		t.Error("ctEq")
	}
}

func TestSameOriginFetch(t *testing.T) {
	tests := []struct {
		header map[string]string
		want   bool
	}{
		{map[string]string{}, true},
		{map[string]string{"sec-fetch-site": "same-origin"}, true},
		{map[string]string{"sec-fetch-site": "none"}, true},
		{map[string]string{"sec-fetch-site": "same-site", "origin": "https://h"}, false},
		{map[string]string{"origin": "https://h"}, true},
		{map[string]string{"origin": "https://other"}, false},
	}
	for _, tt := range tests {
		if got := (&request{header: tt.header}).sameOriginFetch("h"); got != tt.want {
			t.Errorf("sameOriginFetch(%v) = %v, want %v", tt.header, got, tt.want)
		}
	}
}

// TestParseSecrets parses a real identity when SALLYPORT_SECRETS names a
// JSON file of secrets, as `wrangler secret bulk` takes it.
func TestParseSecrets(t *testing.T) {
	path := os.Getenv("SALLYPORT_SECRETS")
	if path == "" {
		t.Skip("SALLYPORT_SECRETS not set")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	env := map[string]string{"CLUSTER_NAME": "sallyport-go"}
	if err := json.Unmarshal(b, &env); err != nil {
		t.Fatal(err)
	}
	c := parseConfig(env)
	for _, err := range c.errs {
		t.Error(err)
	}
	t.Logf("proxy name %q", c.proxyName)
}
