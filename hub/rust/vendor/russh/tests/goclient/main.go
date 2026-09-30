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
	"reflect"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"golang.org/x/crypto/ssh"
)

func main() {
	if len(os.Args) < 3 {
		log.Fatalf("usage: goclient <addr> <scenario> [ca-public-key]")
	}
	addr, scenario := os.Args[1], os.Args[2]
	if scenario == "hostcert" {
		hostCert(addr, os.Args[3], nil)
		return
	}
	if scenario == "hostcert-gex" {
		hostCert(addr, os.Args[3], []string{ssh.KeyExchangeDHGEXSHA256})
		return
	}
	if scenario == "hostkey-plain" {
		hostKeyPlain(addr)
		return
	}
	if scenario == "kex-stall" {
		kexStall(addr)
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
		nc := waitTransport(client)
		fmt.Printf("open-extra=%x\n", nc.ExtraData())
		serveTransport(nc)

	case "transport-close":
		// Close the channel on the first request instead of replying.
		ch, reqs, err := waitTransport(client).Accept()
		if err != nil {
			log.Fatalf("accept: %v", err)
		}
		req := <-reqs
		fmt.Printf("request=%s\n", req.Type)
		ch.Close()
		go ssh.DiscardRequests(reqs)
		// Wait for the server to end the connection.
		client.Wait()

	case "transport-silent":
		// Never reply to a request.
		_, reqs, err := waitTransport(client).Accept()
		if err != nil {
			log.Fatalf("accept: %v", err)
		}
		req := <-reqs
		fmt.Printf("request=%s\n", req.Type)
		go ssh.DiscardRequests(reqs)
		client.Wait()

	case "unconfirmed":
		// Before confirming the server's channel, send requests and data
		// on it. The server must ignore them.
		nc := waitTransport(client)
		id := remoteID(nc)
		writeRaw(client, channelRequestMsg{PeersID: id, Request: "early-reply", WantReply: true})
		writeRaw(client, channelRequestMsg{PeersID: id, Request: "early-quiet"})
		writeRaw(client, channelDataMsg{PeersID: id, Data: []byte("early")})
		writeRaw(client, channelEOFMsg{PeersID: id})
		serveTransport(nc)

	case "dup-confirm":
		// Accept the server's channel, then, with "dup", confirm it a
		// second time. The server must end the connection.
		nc := waitTransport(client)
		ch, reqs, err := nc.Accept()
		if err != nil {
			log.Fatalf("accept: %v", err)
		}
		go ssh.DiscardRequests(reqs)
		if os.Args[3] == "dup" {
			writeRaw(client, channelOpenConfirmMsg{
				PeersID:       remoteID(nc),
				MyID:          localID(nc),
				MyWindow:      1 << 20,
				MaxPacketSize: 1 << 15,
			})
		}
		// A request on a channel the client opens shows whether the
		// connection is still open.
		probe, preqs, err := client.OpenChannel("teleport-heartbeat", nil)
		if err == nil {
			go ssh.DiscardRequests(preqs)
			_, err = probe.SendRequest("probe-true", true, nil)
		}
		fmt.Printf("after-confirm=%v\n", err == nil)
		ch.Close()

	case "late-confirm":
		// Accept the server's first channel only once its second one
		// arrives, which the server opens after it stopped waiting for the
		// first. The server must then close the first channel.
		opens := client.HandleChannelOpen("teleport-transport")
		if _, _, err := client.SendRequest("ready", true, nil); err != nil {
			log.Fatalf("ready: %v", err)
		}
		first, second := <-opens, <-opens
		if first == nil || second == nil {
			log.Fatalf("connection closed before both channels were opened")
		}
		second.Reject(ssh.Prohibited, "")
		_, reqs, err := first.Accept()
		if err != nil {
			log.Fatalf("accept: %v", err)
		}
		// x/crypto closes reqs when the server closes the channel.
		closed := make(chan struct{})
		go func() {
			ssh.DiscardRequests(reqs)
			close(closed)
		}()
		select {
		case <-closed:
			fmt.Println("closed=true")
		case <-time.After(10 * time.Second):
			fmt.Println("closed=false")
		}

	case "oversize-data", "overwindow-data":
		// Send one data packet of the given size on a channel. Go's own
		// writes never exceed the server's packet size or window, so
		// this bypasses them.
		size, err := strconv.Atoi(os.Args[3])
		if err != nil {
			log.Fatalf("size: %v", err)
		}
		ch, reqs, err := client.OpenChannel("teleport-heartbeat", nil)
		if err != nil {
			log.Fatalf("open teleport-heartbeat: %v", err)
		}
		go ssh.DiscardRequests(reqs)
		writeRaw(client, channelDataMsg{PeersID: remoteID(ch), Data: make([]byte, size)})
		// A reply shows that the server kept the connection open.
		_, err = ch.SendRequest("probe-true", true, nil)
		fmt.Printf("after-data=%v\n", err == nil)

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

// waitTransport registers for the server's teleport-transport channel, then
// sends the "ready" global request that tells the server to open it, and
// returns the channel when it arrives.
func waitTransport(client *ssh.Client) ssh.NewChannel {
	opens := client.HandleChannelOpen("teleport-transport")
	if _, _, err := client.SendRequest("ready", true, nil); err != nil {
		log.Fatalf("ready: %v", err)
	}
	nc := <-opens
	if nc == nil {
		log.Fatalf("connection closed before teleport-transport was opened")
	}
	return nc
}

// serveTransport accepts the channel and answers each request on it, with
// success only for teleport-transport-dial, until the server closes it.
func serveTransport(nc ssh.NewChannel) {
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
}

// The wire messages that writeRaw sends. ssh.Marshal encodes them.
type channelRequestMsg struct {
	PeersID   uint32 `sshtype:"98"`
	Request   string
	WantReply bool
	Payload   []byte `ssh:"rest"`
}

type channelDataMsg struct {
	PeersID uint32 `sshtype:"94"`
	Data    []byte
}

type channelOpenConfirmMsg struct {
	PeersID       uint32 `sshtype:"91"`
	MyID          uint32
	MyWindow      uint32
	MaxPacketSize uint32
}

type channelEOFMsg struct {
	PeersID uint32 `sshtype:"96"`
}

// x/crypto/ssh has no API to send a message out of protocol order, so
// writeRaw calls its unexported packet writer.
//
//go:linkname handshakeWritePacket golang.org/x/crypto/ssh.(*handshakeTransport).writePacket
func handshakeWritePacket(t unsafe.Pointer, p []byte) error

func writeRaw(client *ssh.Client, msg any) {
	transport := field(reflect.ValueOf(client.Conn), "transport", "*ssh.handshakeTransport")
	if err := handshakeWritePacket(transport.UnsafePointer(), ssh.Marshal(msg)); err != nil {
		log.Fatalf("write raw: %v", err)
	}
}

// kexStall starts a key exchange and never finishes it. Its host key
// callback blocks on the second call, after the server has sent its reply
// and NEWKEYS, so the server's key exchange stays active. It then sends
// global requests that want a reply until a write fails, and prints whether
// the server ended the connection.
func kexStall(addr string) {
	stalled := make(chan struct{})
	var calls atomic.Int32
	client, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{
		Config: ssh.Config{RekeyThreshold: 256 * 1024},
		User:   "agent",
		HostKeyCallback: func(string, net.Addr, ssh.PublicKey) error {
			if calls.Add(1) == 1 {
				return nil
			}
			close(stalled)
			select {}
		},
	})
	if err != nil {
		log.Fatalf("dial: %v", err)
	}
	ch, reqs, err := client.OpenChannel("teleport-heartbeat", nil)
	if err != nil {
		log.Fatalf("open teleport-heartbeat: %v", err)
	}
	go ssh.DiscardRequests(reqs)
	// The rekey threshold is below this, so the client starts a key
	// exchange.
	go ch.Write(make([]byte, 1<<20))
	<-stalled

	// The key exchange goroutine is blocked, and x/crypto queues every
	// other write, so nothing else writes to the transport.
	transport := field(reflect.ValueOf(client.Conn), "transport", "*ssh.handshakeTransport")
	conn := field(transport, "conn", "*ssh.transport")
	msg := globalRequestMsg{Type: "keepalive@openssh.com", WantReply: true}
	// The server's limit is 4 MiB of queued replies, about 840,000 of
	// them.
	for range 1_200_000 {
		if err := transportWritePacket(conn.UnsafePointer(), ssh.Marshal(msg)); err != nil {
			fmt.Println("disconnected=true")
			return
		}
	}
	fmt.Println("disconnected=false")
}

type globalRequestMsg struct {
	Type      string `sshtype:"80"`
	WantReply bool
}

//go:linkname transportWritePacket golang.org/x/crypto/ssh.(*transport).writePacket
func transportWritePacket(t unsafe.Pointer, p []byte) error

// field returns the value in the interface field name of the struct that
// ptr points to, and exits if its type is not want. The linknamed writers
// take a raw pointer, so a changed x/crypto type would otherwise corrupt
// memory instead of failing the test.
func field(ptr reflect.Value, name, want string) reflect.Value {
	f := ptr.Elem().FieldByName(name)
	if !f.IsValid() || f.Kind() != reflect.Interface || f.IsNil() {
		log.Fatalf("x/crypto has no interface field %s", name)
	}
	if got := f.Elem().Type().String(); got != want {
		log.Fatalf("x/crypto field %s is a %s, want %s", name, got, want)
	}
	return f.Elem()
}

// remoteID returns the server's ID for a channel, from x/crypto's
// unexported channel struct. ch is an ssh.NewChannel or an ssh.Channel.
func remoteID(ch any) uint32 {
	return uint32(reflect.ValueOf(ch).Elem().FieldByName("remoteId").Uint())
}

func localID(ch any) uint32 {
	return uint32(reflect.ValueOf(ch).Elem().FieldByName("localId").Uint())
}

// hostCert connects with the same host key check as a Teleport agent: a
// CertChecker that trusts only the given CA and has no fallback for plain
// host keys. HostKeyAlgorithms is left at its default. If kexes is not nil,
// the client offers only those key exchange algorithms.
func hostCert(addr, caAuthorizedKey string, kexes []string) {
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
		Config: ssh.Config{KeyExchanges: kexes},
		User:   "agent",
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
			// Log the channel error first. Wait returns only once the
			// connection ends, so Close ends it.
			log.Printf("echo: %v", err)
			client.Close()
			log.Fatalf("connection: %v", client.Wait())
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
