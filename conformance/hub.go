package conformance

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"
)

// Hub is a hub under test, served by `wrangler dev` on a local port.
// Requests reach it on Addr, with the host in the Host header.
type Hub struct {
	// Kind is "go" or "rust".
	Kind string
	// Addr is the local listen address, host:port.
	Addr string
	// Vars are the vars the hub runs with.
	Vars map[string]string
	// LogPath is the file `wrangler dev` writes to.
	LogPath string

	cmd  *exec.Cmd
	done chan struct{}
}

// The vars every test hub runs with. The login host is hub.test and app
// hosts are <app>-hub.test.
var baseVars = map[string]string{
	"CLUSTER_NAME":   "sallyport-test",
	"PUBLIC_ADDR":    "hub.test:443",
	"SERVER_VERSION": "18.11.1",
	"CALLOUT_HOST":   "hub.test",
	"DOMAIN":         "test",
	"OWNER":          "hub",
	"APPS":           "bench,cam:/stream",
}

// LoginHost is the test hub's login host.
const LoginHost = "hub.test"

// BaseVars returns a copy of the vars every test hub runs with.
func BaseVars() map[string]string {
	out := make(map[string]string, len(baseVars))
	for k, v := range baseVars {
		out[k] = v
	}
	return out
}

// entries maps a hub kind to its Worker entry, relative to the hub
// directory. Build the hub first with run.sh.
var entries = map[string]string{
	"go":   "worker.mjs",
	"rust": "build/worker/shim.mjs",
}

// StartHub starts `wrangler dev` for the hub in hubDir with vars and
// secrets, in a fresh state directory under dir, and waits until it
// answers.
func StartHub(ctx context.Context, kind, hubDir, dir string, vars, secrets map[string]string) (*Hub, error) {
	entry, ok := entries[kind]
	if !ok {
		return nil, fmt.Errorf("unknown hub kind %q, want go or rust", kind)
	}
	if _, err := os.Stat(filepath.Join(hubDir, entry)); err != nil {
		return nil, fmt.Errorf("hub not built: %w", err)
	}
	if kind == "go" {
		if _, err := os.Stat(filepath.Join(hubDir, "build", "hub.wasm")); err != nil {
			return nil, fmt.Errorf("hub not built: %w", err)
		}
	}
	// wrangler dev reloads when a file it serves changes, and a hub rebuilt
	// during a run would be loaded half written. The hub runs from a copy.
	snap := filepath.Join(dir, "hub")
	if err := copyTree(filepath.Join(hubDir, "build"), filepath.Join(snap, "build")); err != nil {
		return nil, fmt.Errorf("copy hub build: %w", err)
	}
	if kind == "go" {
		if err := copyFile(filepath.Join(hubDir, entry), filepath.Join(snap, entry)); err != nil {
			return nil, fmt.Errorf("copy hub entry: %w", err)
		}
	}
	main := filepath.Join(snap, entry)

	port, err := freePort()
	if err != nil {
		return nil, err
	}
	var toml strings.Builder
	fmt.Fprintf(&toml, "name = \"sallyport-conformance-%s\"\n", kind)
	fmt.Fprintf(&toml, "main = %q\n", main)
	toml.WriteString("compatibility_date = \"2026-09-01\"\n\n")
	toml.WriteString("[[durable_objects.bindings]]\nname = \"HUB\"\nclass_name = \"Hub\"\n\n")
	toml.WriteString("[[migrations]]\ntag = \"v1\"\nnew_sqlite_classes = [\"Hub\"]\n")
	if err := os.WriteFile(filepath.Join(dir, "wrangler.toml"), []byte(toml.String()), 0o600); err != nil {
		return nil, err
	}
	// Vars and secrets both go in .dev.vars, which wrangler reads from the
	// config's directory, so that no var in a hub's own wrangler.toml
	// leaks in.
	all := make(map[string]string)
	for k, v := range vars {
		all[k] = v
	}
	for k, v := range secrets {
		all[k] = v
	}
	keys := make([]string, 0, len(all))
	for k := range all {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var dev strings.Builder
	for _, k := range keys {
		fmt.Fprintf(&dev, "%s=%q\n", k, all[k])
	}
	if err := os.WriteFile(filepath.Join(dir, ".dev.vars"), []byte(dev.String()), 0o600); err != nil {
		return nil, err
	}

	h := &Hub{
		Kind:    kind,
		Addr:    fmt.Sprintf("127.0.0.1:%d", port),
		Vars:    vars,
		LogPath: filepath.Join(dir, "wrangler.log"),
		done:    make(chan struct{}),
	}
	logf, err := os.Create(h.LogPath)
	if err != nil {
		return nil, err
	}
	h.cmd = exec.Command("npx", "wrangler@4", "dev",
		"--config", filepath.Join(dir, "wrangler.toml"),
		"--ip", "127.0.0.1", "--port", fmt.Sprint(port),
		"--inspector-port", "0",
		// Over plain HTTP, wrangler dev rewrites Origin to http://, which no
		// POST check accepts.
		"--local-protocol", "https",
		"--persist-to", filepath.Join(dir, "state"),
		"--show-interactive-dev-session=false",
		"--log-level", "log",
	)
	h.cmd.Dir = dir
	h.cmd.Stdout, h.cmd.Stderr = logf, logf
	// wrangler starts workerd as a child. A process group lets Stop end
	// both.
	h.cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := h.cmd.Start(); err != nil {
		logf.Close()
		return nil, err
	}
	go func() {
		h.cmd.Wait()
		logf.Close()
		close(h.done)
	}()

	ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	for {
		select {
		case <-h.done:
			return nil, fmt.Errorf("wrangler dev exited, see %s", h.LogPath)
		case <-ctx.Done():
			h.Stop()
			return nil, fmt.Errorf("hub did not answer within 90s, see %s", h.LogPath)
		case <-time.After(250 * time.Millisecond):
		}
		resp, err := h.Get(LoginHost, "/webapi/ping")
		if err == nil {
			resp.Body.Close()
			return h, nil
		}
	}
}

// Stop ends `wrangler dev` and its workerd.
func (h *Hub) Stop() {
	if h.cmd == nil || h.cmd.Process == nil {
		return
	}
	syscall.Kill(-h.cmd.Process.Pid, syscall.SIGTERM)
	select {
	case <-h.done:
	case <-time.After(5 * time.Second):
		syscall.Kill(-h.cmd.Process.Pid, syscall.SIGKILL)
		<-h.done
	}
}

// Get sends a GET for path with Host host.
func (h *Hub) Get(host, path string) (*http.Response, error) {
	req, err := http.NewRequest("GET", "https://"+host+path, nil)
	if err != nil {
		return nil, err
	}
	return h.Do(req)
}

// Do sends req to the hub, keeping its Host, and does not follow
// redirects.
func (h *Hub) Do(req *http.Request) (*http.Response, error) {
	return h.Client().Do(req)
}

// Client returns an HTTP client that dials the hub for every host.
func (h *Hub) Client() *http.Client {
	return &http.Client{
		Transport: &http.Transport{DialContext: h.DialContext, TLSClientConfig: EdgeTLS()},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Timeout: 30 * time.Second,
	}
}

// EdgeTLS returns the TLS config toward wrangler dev, whose certificate is
// self-signed. It stands in for Cloudflare's edge, so it is not checked.
func EdgeTLS() *tls.Config { return &tls.Config{InsecureSkipVerify: true} }

// DialContext dials the hub whatever the address.
func (h *Hub) DialContext(ctx context.Context, _, _ string) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, "tcp", h.Addr)
}

// LogHas returns true when the hub log has a line that contains s.
func (h *Hub) LogHas(s string) bool {
	b, err := os.ReadFile(h.LogPath)
	return err == nil && strings.Contains(string(b), s)
}

// LogTail returns the last n lines of the hub log.
func (h *Hub) LogTail(n int) string {
	b, err := os.ReadFile(h.LogPath)
	if err != nil {
		return err.Error()
	}
	lines := strings.Split(strings.TrimRight(string(b), "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}

func freePort() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}

// copyTree copies the regular files under src to dst.
func copyTree(src, dst string) error {
	return filepath.WalkDir(src, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		if d.IsDir() {
			return os.MkdirAll(filepath.Join(dst, rel), 0o700)
		}
		if !d.Type().IsRegular() {
			return nil
		}
		return copyFile(path, filepath.Join(dst, rel))
	})
}

func copyFile(src, dst string) error {
	b, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		return err
	}
	return os.WriteFile(dst, b, 0o600)
}
