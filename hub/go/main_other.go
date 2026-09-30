//go:build !(js && wasm)

package main

// The hub runs only as js/wasm in a Durable Object. This file lets the
// portable parts build and test natively.

type (
	wsConn     struct{}
	bodyStream struct{}
)

func main() {}
