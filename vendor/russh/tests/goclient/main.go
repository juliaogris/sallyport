// Command goclient drives a russh server with golang.org/x/crypto/ssh, the
// SSH library that Teleport agents use. It prints one key=value line per
// observation and exits non-zero on an unexpected error.
package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/crypto/ssh"
)

func main() {
	if len(os.Args) < 3 {
		log.Fatalf("usage: goclient <addr> <scenario> [ca-public-key]")
	}
	addr, scenario := os.Args[1], os.Args[2]
	if scenario == "hostcert" {
		hostCert(addr, os.Args[3])
		return
	}
	if scenario == "hostkey-plain" {
		hostKeyPlain(addr)
		return
	}

	client, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{
		User:            "agent",
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	})
	if err != nil {
		log.Fatalf("dial: %v", err)
	}
	defer client.Close()

	switch scenario {
	case "open":
		ch, _, err := client.OpenChannel("teleport-heartbeat", nil)
		if err != nil {
			log.Fatalf("open teleport-heartbeat: %v", err)
		}
		ch.Close()
		fmt.Println("heartbeat=ok")
		_, _, err = client.OpenChannel("teleport-refused", nil)
		var openErr *ssh.OpenChannelError
		if !errors.As(err, &openErr) {
			log.Fatalf("open teleport-refused: want OpenChannelError, got %v", err)
		}
		fmt.Printf("refused=%s\n", openErr.Reason)

	case "chanreq":
		ch, _, err := client.OpenChannel("teleport-heartbeat", nil)
		if err != nil {
			log.Fatalf("open teleport-heartbeat: %v", err)
		}
		// The handler returns false for ping. If the server replied anyway,
		// the stray failure would be read as the answer to probe-true below.
		if _, err := ch.SendRequest("ping", false, []byte{1, 2, 3}); err != nil {
			log.Fatalf("ping: %v", err)
		}
		ok, err := ch.SendRequest("probe-true", true, []byte("t"))
		if err != nil {
			log.Fatalf("probe-true: %v", err)
		}
		fmt.Printf("probe-true=%v\n", ok)
		ok, err = ch.SendRequest("probe-false", true, nil)
		if err != nil {
			log.Fatalf("probe-false: %v", err)
		}
		fmt.Printf("probe-false=%v\n", ok)

	case "global":
		ok, _, err := client.SendRequest("keepalive@openssh.com", true, nil)
		if err != nil {
			log.Fatalf("keepalive want_reply=true: %v", err)
		}
		fmt.Printf("keepalive-reply=%v\n", ok)
		// The handler returns true for keepalive. If the server replied anyway,
		// the stray success would be read as the answer to probe-false below.
		if _, _, err := client.SendRequest("keepalive@openssh.com", false, nil); err != nil {
			log.Fatalf("keepalive want_reply=false: %v", err)
		}
		ok, _, err = client.SendRequest("probe-false", true, nil)
		if err != nil {
			log.Fatalf("probe-false: %v", err)
		}
		fmt.Printf("probe-false=%v\n", ok)

	case "transport":
		nc := <-client.HandleChannelOpen("teleport-transport")
		if nc == nil {
			log.Fatalf("connection closed before teleport-transport was opened")
		}
		fmt.Printf("open-extra=%x\n", nc.ExtraData())
		ch, reqs, err := nc.Accept()
		if err != nil {
			log.Fatalf("accept: %v", err)
		}
		defer ch.Close()
		for req := range reqs {
			fmt.Printf("request=%s:%x\n", req.Type, req.Payload)
			if err := req.Reply(req.Type == "teleport-transport-dial", nil); err != nil {
				log.Fatalf("reply: %v", err)
			}
		}

	case "rekey-echo":
		channels, err := strconv.Atoi(os.Args[3])
		if err != nil {
			log.Fatalf("channels: %v", err)
		}
		size, err := strconv.Atoi(os.Args[4])
		if err != nil {
			log.Fatalf("size: %v", err)
		}
		rekeyEcho(client, channels, size)

	default:
		log.Fatalf("unknown scenario %q", scenario)
	}
}

// hostCert connects with the same host key check as a Teleport agent: a
// CertChecker that trusts only the given CA and has no fallback for plain
// host keys. HostKeyAlgorithms is left at its default.
func hostCert(addr, caAuthorizedKey string) {
	caPub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(caAuthorizedKey))
	if err != nil {
		log.Fatalf("parse CA key: %v", err)
	}
	checker := &ssh.CertChecker{
		IsHostAuthority: func(k ssh.PublicKey, _ string) bool {
			return bytes.Equal(k.Marshal(), caPub.Marshal())
		},
	}
	var seen *ssh.Certificate
	client, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{
		User: "agent",
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			if cert, ok := key.(*ssh.Certificate); ok {
				seen = cert
			}
			return checker.CheckHostKey(hostname, remote, key)
		},
	})
	if err != nil {
		fmt.Printf("handshake=failed: %v\n", err)
		return
	}
	defer client.Close()
	fmt.Println("handshake=ok")
	if seen != nil {
		fmt.Printf("cert-principals=%s\n", strings.Join(seen.ValidPrincipals, ","))
	}
}

// hostKeyPlain offers only the plain ECDSA host key algorithm, so a server
// with a host certificate must fall back to its plain public key.
func hostKeyPlain(addr string) {
	var keyType string
	client, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{
		User:              "agent",
		HostKeyAlgorithms: []string{ssh.KeyAlgoECDSA256},
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			keyType = key.Type()
			return nil
		},
	})
	if err != nil {
		log.Fatalf("dial: %v", err)
	}
	defer client.Close()
	fmt.Printf("host-key-type=%s\n", keyType)
}

// rekeyEcho opens the given number of teleport-echo channels at once. On
// each it writes size random bytes, sends EOF and reads the echo back to
// EOF. The connection fails if the server sends a non-kex message during
// one of its key exchanges.
func rekeyEcho(client *ssh.Client, channels, size int) {
	errs := make(chan error, channels)
	var wg sync.WaitGroup
	for i := range channels {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- echoOne(client, int64(i), size)
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			log.Fatalf("echo: %v (connection: %v)", err, client.Wait())
		}
	}
	fmt.Printf("echo=ok channels=%d size=%d\n", channels, size)
}

func echoOne(client *ssh.Client, seed int64, size int) error {
	ch, reqs, err := client.OpenChannel("teleport-echo", nil)
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}
	defer ch.Close()
	go ssh.DiscardRequests(reqs)

	want := make([]byte, size)
	rand.New(rand.NewSource(seed)).Read(want)
	writeErr := make(chan error, 1)
	go func() {
		// Several writes, so that the server's window adjusts arrive
		// while data is in flight both ways.
		for off := 0; off < size; off += 100_000 {
			end := min(off+100_000, size)
			if _, err := ch.Write(want[off:end]); err != nil {
				writeErr <- fmt.Errorf("write: %w", err)
				return
			}
		}
		writeErr <- ch.CloseWrite()
	}()
	got, err := io.ReadAll(ch)
	if err != nil {
		return fmt.Errorf("read after %d bytes: %w", len(got), err)
	}
	if err := <-writeErr; err != nil {
		return err
	}
	if !bytes.Equal(got, want) {
		return fmt.Errorf("channel %d: got %d bytes, want %d, or they differ", seed, len(got), size)
	}
	return nil
}
