// Command goclient drives a russh server with golang.org/x/crypto/ssh, the
// SSH library that Teleport agents use. It prints one key=value line per
// observation and exits non-zero on an unexpected error.
package main

import (
	"errors"
	"fmt"
	"log"
	"os"

	"golang.org/x/crypto/ssh"
)

func main() {
	if len(os.Args) != 3 {
		log.Fatalf("usage: goclient <addr> <scenario>")
	}
	addr, scenario := os.Args[1], os.Args[2]

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

	default:
		log.Fatalf("unknown scenario %q", scenario)
	}
}
