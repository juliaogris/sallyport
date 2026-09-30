// Command localstack runs a hub under `wrangler dev` with the fake auth
// behind its callout and a fake agent that serves the test app, then
// prints an app session for the load command and waits until interrupted.
//
//	localstack -hub go
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"time"

	"github.com/juliaogris/sallyport/conformance"
	"github.com/juliaogris/sallyport/conformance/testapp"
)

func main() {
	kind := flag.String("hub", "go", "go or rust")
	hubDir := flag.String("hub-dir", "", "the hub directory, by default ../hub/<hub>")
	streams := flag.Int("streams", 8, "callout streams to keep open")
	flag.Parse()
	if *hubDir == "" {
		*hubDir = filepath.Join("..", "hub", *kind)
	}
	abs, err := filepath.Abs(*hubDir)
	if err != nil {
		log.Fatal(err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	dir, err := os.MkdirTemp("", "sallyport-localstack-"+*kind+"-")
	if err != nil {
		log.Fatal(err)
	}
	p, err := conformance.NewPKI(conformance.BaseVars()["CLUSTER_NAME"], conformance.LoginHost)
	if err != nil {
		log.Fatal(err)
	}
	h, err := conformance.StartHub(ctx, *kind, abs, dir, conformance.BaseVars(), p.Secrets())
	if err != nil {
		log.Fatal(err)
	}
	defer h.Stop()
	auth, err := conformance.NewFakeAuth(p)
	if err != nil {
		log.Fatal(err)
	}
	defer auth.Close()
	auth.Run(ctx, h, *streams)

	id, err := p.AgentIdentity("App")
	if err != nil {
		log.Fatal(err)
	}
	a, err := h.DialAgent(ctx, p, id)
	if err != nil {
		log.Fatal(err)
	}
	defer a.Close()
	if err := a.ServeApp(p, testapp.Handler("")); err != nil {
		log.Fatal(err)
	}
	if _, ok, err := a.Heartbeat(); err != nil || !ok {
		log.Fatalf("heartbeat: %v %v", ok, err)
	}
	time.Sleep(time.Second)
	sid, bearer, err := conformance.AppSession(h, "bench")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("hub %s on %s, log %s\n", *kind, h.Addr, h.LogPath)
	fmt.Printf("go run ./cmd/load -url https://bench-hub.test -connect %s -insecure -sid %s -bearer %s\n", h.Addr, sid, bearer)
	<-ctx.Done()
}
