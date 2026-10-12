package conformance

import (
	"flag"
	"io"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/juliaogris/sallyport/conformance/testapp"
	"github.com/stretchr/testify/require"
)

var long = flag.Bool("long", false, "run the tests that move gigabytes")

// TestSlowReader checks that a download the browser stops reading does
// not stall other requests through the same tunnel.
func TestSlowReader(t *testing.T) {
	s := newStack(t)
	cookies := s.appCookies(t, "bench")
	host := appHost("bench")

	// Read 1 MiB of a 256 MiB download, then stop reading.
	stalled := s.get(t, host, "/t/bytes?n="+itoa(256<<20), cookies...)
	defer stalled.Body.Close()
	require.Equal(t, http.StatusOK, stalled.StatusCode)
	_, err := io.CopyN(io.Discard, stalled.Body, 1<<20)
	require.NoError(t, err)
	time.Sleep(2 * time.Second)

	for i := range 10 {
		start := time.Now()
		resp := s.get(t, host, "/t/static", cookies...)
		body := readBody(t, resp)
		require.Equal(t, http.StatusOK, resp.StatusCode)
		require.Equal(t, testapp.StaticBody, body)
		require.Less(t, time.Since(start), 3*time.Second, "request %d behind a stalled download", i)
	}

	// A second download completes while the first is still stalled.
	start := time.Now()
	resp := s.get(t, host, "/t/bytes?n="+itoa(16<<20), cookies...)
	n, err := io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	require.NoError(t, err)
	require.EqualValues(t, 16<<20, n)
	t.Logf("16 MiB beside a stalled download in %v", time.Since(start))
}

// TestParallelDownloads checks that 8 downloads at once all complete
// intact, and again with the agent rekeying every 256 KiB, so that key
// exchanges start while channels are busy.
func TestParallelDownloads(t *testing.T) {
	t.Run("default", func(t *testing.T) { parallelDownloads(t, newStack(t)) })
	t.Run("rekey every 256 KiB", func(t *testing.T) {
		parallelDownloads(t, newStack(t, WithRekeyThreshold(256<<10)))
	})
}

func parallelDownloads(t *testing.T, s *stack) {
	cookies := s.appCookies(t, "bench")
	const n, size = 8, 16 << 20
	var wg sync.WaitGroup
	errs := make([]error, n)
	got := make([]int64, n)
	start := time.Now()
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req, _ := http.NewRequest("GET", "https://"+appHost("bench")+"/t/bytes?n="+itoa(size), nil)
			for _, c := range cookies {
				req.AddCookie(c)
			}
			resp, err := s.hub.Do(req)
			if err != nil {
				errs[i] = err
				return
			}
			defer resp.Body.Close()
			got[i], errs[i] = io.Copy(io.Discard, resp.Body)
		}()
	}
	wg.Wait()
	took := time.Since(start)
	for i := range n {
		require.NoError(t, errs[i], "download %d", i)
		require.EqualValues(t, size, got[i], "download %d", i)
	}
	t.Logf("%d x %d MiB in %v, %.1f MiB/s", n, size>>20, took, float64(n*size>>20)/took.Seconds())
}

// TestRekey checks that 2 GiB through one tunnel completes. With
// chacha20-poly1305, SSH rekeys after every 1 GiB, so the download can
// cross a rekey the hub starts. It runs only with -long.
func TestRekey(t *testing.T) {
	if !*long {
		t.Skip("moves 2 GiB; run with -long")
	}
	s := newStack(t)
	cookies := s.appCookies(t, "bench")
	const size = 2 << 30
	start := time.Now()
	req, _ := http.NewRequest("GET", "https://"+appHost("bench")+"/t/bytes?n="+itoa(size), nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	cl := s.hub.Client()
	cl.Timeout = 30 * time.Minute
	resp, err := cl.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	n, err := io.Copy(io.Discard, resp.Body)
	require.NoError(t, err)
	require.EqualValues(t, size, n)
	took := time.Since(start)
	t.Logf("2 GiB in %v, %.1f MiB/s", took, float64(size>>20)/took.Seconds())

	// The tunnel still works after the rekey.
	resp2 := s.get(t, appHost("bench"), "/t/static", cookies...)
	readBody(t, resp2)
	require.Equal(t, http.StatusOK, resp2.StatusCode)
}
