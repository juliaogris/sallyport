package conformance

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// The hub under test. SP_HUB is go or rust. SP_HUB_DIR is the hub's
// directory, by default ../hub/go or ../hub/rust.
var (
	hubKind = os.Getenv("SP_HUB")
	hubDir  = os.Getenv("SP_HUB_DIR")
	keep    = flag.Bool("keep", false, "keep the hub's state and logs after the run")
)

var (
	pki    *PKI
	shared *Hub
	tmp    string
)

func TestMain(m *testing.M) {
	flag.Parse()
	os.Exit(run(m))
}

func run(m *testing.M) int {
	if hubKind == "" {
		fmt.Fprintln(os.Stderr, "SP_HUB must be go or rust; see run.sh")
		return 2
	}
	if hubDir == "" {
		hubDir = filepath.Join("..", "hub", hubKind)
	}
	abs, err := filepath.Abs(hubDir)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	hubDir = abs

	if tmp, err = os.MkdirTemp("", "sallyport-conformance-"+hubKind+"-"); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	if !*keep {
		defer os.RemoveAll(tmp)
	}
	if pki, err = NewPKI(baseVars["CLUSTER_NAME"], LoginHost); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	dir := filepath.Join(tmp, "shared")
	if err := os.Mkdir(dir, 0o700); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	if shared, err = StartHub(context.Background(), hubKind, hubDir, dir, BaseVars(), pki.Secrets()); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	defer shared.Stop()
	fmt.Fprintf(os.Stderr, "hub %s on %s, log %s\n", hubKind, shared.Addr, shared.LogPath)
	return m.Run()
}

// freshHub starts a hub of its own for a test that needs a clean pool or
// connection count.
func freshHub(t *testing.T) *Hub {
	t.Helper()
	dir := filepath.Join(tmp, t.Name())
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	h, err := StartHub(t.Context(), hubKind, hubDir, dir, BaseVars(), pki.Secrets())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(h.Stop)
	logOnFailure(t, h)
	return h
}

// logOnFailure prints the end of the hub log when t fails.
func logOnFailure(t *testing.T, h *Hub) {
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("hub log (%s), last 40 lines:\n%s", h.LogPath, h.LogTail(40))
		}
	})
}
