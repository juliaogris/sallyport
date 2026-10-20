package main

import (
	"crypto/rand"
	"encoding/hex"
	"strings"
)

// newState returns a new launch state and its secret and ID parts.
func newState() (state, secret, id string) {
	secret, id = randomHex(), randomHex()
	return secret + "_" + id, secret, id
}

// randomHex returns 32 random bytes as hex.
func randomHex() string {
	var b [32]byte
	rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// parseState splits a launch state into its secret and ID, which are each
// 64 lowercase hex digits joined by "_".
func parseState(state string) (secret, id string, ok bool) {
	secret, id, ok = strings.Cut(state, "_")
	if !ok || !isHex64(secret) || !isHex64(id) {
		return "", "", false
	}
	return secret, id, true
}

func isHex64(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}
