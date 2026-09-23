// Command probe runs Teleport's own ALPN connection upgrade probe against
// an address and prints the result, plus the raw TLS handshake outcome
// that the probe bases its decision on.
package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"os"
	"time"

	"github.com/gravitational/teleport/api/client"
	"github.com/gravitational/teleport/api/constants"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: probe host:port")
		os.Exit(2)
	}
	addr := os.Args[1]
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	os.Unsetenv("TELEPORT_TLS_ROUTING_CONN_UPGRADE")
	required := client.IsALPNConnUpgradeRequired(ctx, addr, false)
	fmt.Printf("IsALPNConnUpgradeRequired(%s) = %v\n", addr, required)

	conn, err := tls.Dial("tcp", addr, &tls.Config{
		NextProtos: []string{string(constants.ALPNSNIProtocolReverseTunnel)},
	})
	if err != nil {
		fmt.Printf("raw handshake error: %v\n", err)
		return
	}
	defer conn.Close()
	st := conn.ConnectionState()
	fmt.Printf("raw handshake ok: negotiated ALPN %q, TLS version %#x\n", st.NegotiatedProtocol, st.Version)
}
