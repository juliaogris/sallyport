// Command load sends browser-like traffic to the test app behind a hub and
// prints latency, throughput and errors per kind of request.
//
// It needs an app session: the session ID and bearer token that are the
// values of the __Host-sp_app and __Host-sp_subject cookies. -session reads
// them from a directory with the files session-id and bearer-token, as
// appsessmint writes them.
//
//	load -url https://bench-go.example.com -session DIR -scenario mix -c 8 -d 5m
//
// Scenarios:
//
//   - small: GET /t/static in a loop, for latency.
//   - page: GET /t/page and its 50 assets, 6 at a time like a browser.
//   - bulk: GET 10 MiB in a loop, for throughput.
//   - upload: POST 5 MiB in a loop.
//   - stream: one MJPEG stream per worker for the whole run, with frame gaps.
//   - mix: 2 streams, and the other workers pick small, page, 1 MiB
//     downloads, 1 MiB uploads, gzip and 304 by weight.
//
// Every scenario also runs a canary that sends GET /t/static once a second,
// so the latency of a small request under load is always measured.
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math/rand/v2"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"
)

type config struct {
	base     string
	host     string
	sid      string
	bearer   string
	client   *http.Client
	scenario string
	workers  int
	duration time.Duration
}

func main() {
	var c config
	flag.StringVar(&c.base, "url", "", "the app host, such as https://bench-go.example.com")
	connect := flag.String("connect", "", "dial this host:port for every request, such as a wrangler dev address")
	insecure := flag.Bool("insecure", false, "do not check the TLS certificate")
	session := flag.String("session", "", "a directory with session-id and bearer-token")
	flag.StringVar(&c.sid, "sid", "", "the app session ID")
	flag.StringVar(&c.bearer, "bearer", "", "the app session bearer token")
	flag.StringVar(&c.scenario, "scenario", "mix", "small, page, bulk, upload, stream or mix")
	flag.IntVar(&c.workers, "c", 8, "concurrent workers")
	flag.DurationVar(&c.duration, "d", time.Minute, "how long to run")
	jsonOut := flag.String("json", "", "also write the results as JSON to this file")
	label := flag.String("label", "", "a label for the JSON results, such as the hub")
	flag.Parse()

	if *session != "" {
		c.sid, c.bearer = readFile(*session, "session-id"), readFile(*session, "bearer-token")
	}
	if c.base == "" || c.sid == "" || c.bearer == "" {
		log.Fatal("need -url and an app session (-session, or -sid and -bearer)")
	}
	c.host = strings.TrimPrefix(strings.TrimPrefix(c.base, "https://"), "http://")
	tr := &http.Transport{
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: *insecure},
		MaxIdleConnsPerHost: 64,
		DisableCompression:  true,
		ForceAttemptHTTP2:   true,
	}
	if *connect != "" {
		tr.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, *connect)
		}
	}
	c.client = &http.Client{
		Transport: tr,
		Timeout:   5 * time.Minute,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, c.duration)
	defer cancel()

	st := newStats()
	start := time.Now()
	run(ctx, &c, st)
	elapsed := time.Since(start)
	res := st.results(elapsed)
	printResults(res, elapsed)
	if *jsonOut != "" {
		out := map[string]any{
			"label": *label, "url": c.base, "scenario": c.scenario, "workers": c.workers,
			"seconds": elapsed.Seconds(), "started": start.UTC().Format(time.RFC3339), "kinds": res,
		}
		b, _ := json.MarshalIndent(out, "", "  ")
		if err := os.WriteFile(*jsonOut, b, 0o644); err != nil {
			log.Fatal(err)
		}
	}
}

func readFile(dir, name string) string {
	b, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		log.Fatal(err)
	}
	return strings.TrimSpace(string(b))
}

func run(ctx context.Context, c *config, st *stats) {
	var wg sync.WaitGroup
	spawn := func(f func()) {
		wg.Add(1)
		go func() { defer wg.Done(); f() }()
	}
	spawn(func() { canary(ctx, c, st) })
	switch c.scenario {
	case "stream":
		for range c.workers {
			spawn(func() { stream(ctx, c, st) })
		}
	case "mix":
		for i := range c.workers {
			if i < 2 {
				spawn(func() { stream(ctx, c, st) })
			} else {
				spawn(func() { loop(ctx, func() { mixOne(ctx, c, st) }) })
			}
		}
	default:
		one, ok := map[string]func(context.Context, *config, *stats){
			"small": small, "page": page, "bulk": bulk, "upload": upload,
		}[c.scenario]
		if !ok {
			log.Fatalf("unknown scenario %q", c.scenario)
		}
		for range c.workers {
			spawn(func() { loop(ctx, func() { one(ctx, c, st) }) })
		}
	}
	wg.Wait()
}

func loop(ctx context.Context, f func()) {
	for ctx.Err() == nil {
		f()
	}
}

func mixOne(ctx context.Context, c *config, st *stats) {
	switch r := rand.IntN(100); {
	case r < 60:
		small(ctx, c, st)
	case r < 75:
		page(ctx, c, st)
	case r < 85:
		fetch(ctx, c, st, "download-1m", "GET", "/t/bytes?len=1&n=1048576", nil)
	case r < 92:
		fetch(ctx, c, st, "upload-1m", "POST", "/t/upload", payload(1<<20))
	case r < 96:
		fetch(ctx, c, st, "gzip", "GET", "/t/gzip", nil)
	default:
		fetch(ctx, c, st, "304", "GET", "/t/status/304", nil)
	}
}

func canary(ctx context.Context, c *config, st *stats) {
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			fetch(ctx, c, st, "canary", "GET", "/t/static", nil)
		}
	}
}

func small(ctx context.Context, c *config, st *stats) {
	fetch(ctx, c, st, "small", "GET", "/t/static", nil)
}

func bulk(ctx context.Context, c *config, st *stats) {
	fetch(ctx, c, st, "download-10m", "GET", "/t/bytes?len=1&n=10485760", nil)
}

func upload(ctx context.Context, c *config, st *stats) {
	fetch(ctx, c, st, "upload-5m", "POST", "/t/upload", payload(5<<20))
}

// page loads /t/page and then its 50 assets over 6 connections, and
// records the whole page load as one sample.
func page(ctx context.Context, c *config, st *stats) {
	start := time.Now()
	if !fetch(ctx, c, st, "page-html", "GET", "/t/page", nil) {
		return
	}
	jobs := make(chan int)
	var wg sync.WaitGroup
	var mu sync.Mutex
	ok := true
	for range 6 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobs {
				if !fetch(ctx, c, st, "asset", "GET", fmt.Sprintf("/t/asset/%d", i), nil) {
					mu.Lock()
					ok = false
					mu.Unlock()
				}
			}
		}()
	}
	for i := range 50 {
		jobs <- i
	}
	close(jobs)
	wg.Wait()
	if ctx.Err() != nil {
		return
	}
	d := time.Since(start)
	if ok {
		st.add("page-load", sample{ttfb: d, total: d})
	} else {
		st.add("page-load", sample{err: "asset failed"})
	}
}

// stream reads one MJPEG stream until ctx ends and records each gap
// between frames as a sample of kind stream-gap.
func stream(ctx context.Context, c *config, st *stats) {
	for ctx.Err() == nil {
		req, _ := http.NewRequestWithContext(ctx, "GET", c.base+"/t/mjpeg?fps=10", nil)
		c.cookies(req)
		start := time.Now()
		resp, err := c.client.Do(req)
		if err != nil {
			if ctx.Err() == nil {
				st.add("stream-open", sample{err: errText(err)})
				time.Sleep(time.Second)
			}
			continue
		}
		if resp.StatusCode != http.StatusOK {
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			st.add("stream-open", sample{err: fmt.Sprintf("status %d", resp.StatusCode)})
			time.Sleep(time.Second)
			continue
		}
		st.add("stream-open", sample{ttfb: time.Since(start), total: time.Since(start)})
		br := bufio.NewReaderSize(resp.Body, 64<<10)
		last := time.Now()
		var n int64
		for {
			line, err := br.ReadSlice('\n')
			n += int64(len(line))
			if err != nil && !errors.Is(err, bufio.ErrBufferFull) {
				if ctx.Err() == nil {
					st.add("stream-gap", sample{err: "stream ended: " + errText(err)})
				}
				break
			}
			if bytes.HasPrefix(line, []byte("--frame")) {
				now := time.Now()
				st.add("stream-gap", sample{ttfb: now.Sub(last), total: now.Sub(last), bytes: n})
				last, n = now, 0
			}
		}
		resp.Body.Close()
	}
}

func (c *config) cookies(req *http.Request) {
	req.Header.Set("Cookie", "__Host-sp_app="+c.sid+"; __Host-sp_subject="+c.bearer)
	req.Header.Set("User-Agent", "sallyport-load")
}

var payloads sync.Map

func payload(n int) []byte {
	if b, ok := payloads.Load(n); ok {
		return b.([]byte)
	}
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i)
	}
	payloads.Store(n, b)
	return b
}

// fetch sends one request and records it under kind. It returns true when
// the status is 2xx or 304 and the body was read to the end.
func fetch(ctx context.Context, c *config, st *stats, kind, method, path string, body []byte) bool {
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, _ := http.NewRequestWithContext(ctx, method, c.base+path, rd)
	c.cookies(req)
	if method == "POST" {
		req.Header.Set("Origin", c.base)
		req.Header.Set("Sec-Fetch-Site", "same-origin")
	}
	start := time.Now()
	resp, err := c.client.Do(req)
	if err != nil {
		if ctx.Err() == nil {
			st.add(kind, sample{err: errText(err)})
		}
		return false
	}
	ttfb := time.Since(start)
	n, err := io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	total := time.Since(start)
	if ctx.Err() != nil {
		return false
	}
	s := sample{ttfb: ttfb, total: total, bytes: n + int64(len(body))}
	switch {
	case err != nil:
		s.err = "body: " + errText(err)
	case resp.StatusCode >= 300 && resp.StatusCode != 304:
		s.err = fmt.Sprintf("status %d", resp.StatusCode)
	}
	st.add(kind, s)
	return s.err == ""
}

func errText(err error) string {
	s := err.Error()
	if i := strings.LastIndex(s, ": "); i >= 0 && len(s)-i < 80 {
		return s[i+2:]
	}
	return s
}

type sample struct {
	ttfb, total time.Duration
	bytes       int64
	err         string
}

type stats struct {
	mu    sync.Mutex
	kinds map[string][]sample
}

func newStats() *stats { return &stats{kinds: map[string][]sample{}} }

func (s *stats) add(kind string, v sample) {
	s.mu.Lock()
	s.kinds[kind] = append(s.kinds[kind], v)
	s.mu.Unlock()
}

// result is the summary of one kind of request. Times are in
// milliseconds.
type result struct {
	Kind      string         `json:"kind"`
	OK        int            `json:"ok"`
	Errors    map[string]int `json:"errors,omitempty"`
	TTFBp50   float64        `json:"ttfb_p50_ms"`
	TTFBp95   float64        `json:"ttfb_p95_ms"`
	P50       float64        `json:"p50_ms"`
	P95       float64        `json:"p95_ms"`
	P99       float64        `json:"p99_ms"`
	Max       float64        `json:"max_ms"`
	MiBPerSec float64        `json:"mib_per_s"`
}

func (s *stats) results(elapsed time.Duration) []result {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []result
	for kind, vs := range s.kinds {
		r := result{Kind: kind, Errors: map[string]int{}}
		var ttfb, total []time.Duration
		var bytes int64
		for _, v := range vs {
			if v.err != "" {
				r.Errors[v.err]++
				continue
			}
			r.OK++
			ttfb, total = append(ttfb, v.ttfb), append(total, v.total)
			bytes += v.bytes
		}
		slices.Sort(ttfb)
		slices.Sort(total)
		r.TTFBp50, r.TTFBp95 = pct(ttfb, 50), pct(ttfb, 95)
		r.P50, r.P95, r.P99, r.Max = pct(total, 50), pct(total, 95), pct(total, 99), pct(total, 100)
		r.MiBPerSec = float64(bytes) / (1 << 20) / elapsed.Seconds()
		if len(r.Errors) == 0 {
			r.Errors = nil
		}
		out = append(out, r)
	}
	slices.SortFunc(out, func(a, b result) int { return strings.Compare(a.Kind, b.Kind) })
	return out
}

func pct(d []time.Duration, p int) float64 {
	if len(d) == 0 {
		return 0
	}
	i := min(len(d)-1, (len(d)*p)/100)
	return float64(d[i].Microseconds()) / 1000
}

func printResults(res []result, elapsed time.Duration) {
	fmt.Printf("%.0fs\n%-13s %7s %6s %9s %9s %9s %9s %9s %8s\n", elapsed.Seconds(),
		"kind", "ok", "err", "ttfb p50", "p50", "p95", "p99", "max", "MiB/s")
	for _, r := range res {
		errs := 0
		for _, n := range r.Errors {
			errs += n
		}
		fmt.Printf("%-13s %7d %6d %9.1f %9.1f %9.1f %9.1f %9.1f %8.2f\n",
			r.Kind, r.OK, errs, r.TTFBp50, r.P50, r.P95, r.P99, r.Max, r.MiBPerSec)
	}
	for _, r := range res {
		for e, n := range r.Errors {
			fmt.Printf("  %s: %d x %s\n", r.Kind, n, e)
		}
	}
}
