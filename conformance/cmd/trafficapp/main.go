// Command trafficapp serves the test app on a local port, for an app
// service to publish. Paths outside /t/ are served from -dir, so it can
// replace a plain file server.
//
//	trafficapp -addr 127.0.0.1:18080 -dir ~/sallyport/bench
package main

import (
	"flag"
	"log"
	"net/http"

	"github.com/juliaogris/sallyport/conformance/testapp"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:18180", "the listen address")
	dir := flag.String("dir", "", "serve paths outside /t/ from this directory")
	flag.Parse()
	log.Printf("trafficapp on %s, files from %q", *addr, *dir)
	log.Fatal(http.ListenAndServe(*addr, testapp.Handler(*dir)))
}
