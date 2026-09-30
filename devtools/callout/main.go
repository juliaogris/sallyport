// Command devcallout stands in for auth's callout when testing a hub that
// auth does not call out to, such as the dev Worker. It keeps streams open
// to the hub's /tunnel/auth, answers the challenge with the callout key,
// and copies each stream to auth's listener once the hub starts using it,
// which is what auth's own callout pool does.
//
//	devcallout -url wss://HOST/tunnel/auth -key callout.pem -auth 127.0.0.1:3226
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"io"
	"log"
	"net"
	"net/url"
	"os"
	"time"

	"github.com/gorilla/websocket"
)

func main() {
	rawURL := flag.String("url", "", "the hub's wss:// /tunnel/auth URL")
	keyPath := flag.String("key", "", "the Ed25519 callout key, PKCS #8 PEM")
	authAddr := flag.String("auth", "127.0.0.1:3226", "auth's listener")
	size := flag.Int("n", 4, "streams to keep open")
	flag.Parse()
	u, err := url.Parse(*rawURL)
	if err != nil {
		log.Fatal(err)
	}
	pemBytes, err := os.ReadFile(*keyPath)
	if err != nil {
		log.Fatal(err)
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		log.Fatal("no PEM block")
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		log.Fatal(err)
	}
	key := k.(ed25519.PrivateKey)
	for i := range *size {
		go func() {
			for {
				if err := serve(u, key, *authAddr); err != nil {
					log.Printf("stream %d: %v", i, err)
				}
				time.Sleep(time.Second)
			}
		}()
	}
	select {}
}

func serve(u *url.URL, key ed25519.PrivateKey, authAddr string) error {
	ws, _, err := websocket.DefaultDialer.Dial(u.String(), nil)
	if err != nil {
		return err
	}
	defer ws.Close()
	_, hubNonce, err := ws.ReadMessage()
	if err != nil {
		return err
	}
	authNonce := make([]byte, 32)
	rand.Read(authNonce)
	msg := append(append(append([]byte("sallyport/authpipe/v1"), u.Host...), hubNonce...), authNonce...)
	if err := ws.WriteMessage(websocket.BinaryMessage, append(authNonce, ed25519.Sign(key, msg)...)); err != nil {
		return err
	}
	_, first, err := ws.ReadMessage()
	if err != nil {
		return err
	}
	conn, err := net.Dial("tcp", authAddr)
	if err != nil {
		return err
	}
	defer conn.Close()
	log.Printf("stream in use")
	if _, err := conn.Write(first); err != nil {
		return err
	}
	go func() {
		buf := make([]byte, 64<<10)
		for {
			n, err := conn.Read(buf)
			if n > 0 {
				if ws.WriteMessage(websocket.BinaryMessage, buf[:n]) != nil {
					break
				}
			}
			if err != nil {
				break
			}
		}
		ws.Close()
	}()
	for {
		_, b, err := ws.ReadMessage()
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
		if _, err := conn.Write(b); err != nil {
			return err
		}
	}
}
