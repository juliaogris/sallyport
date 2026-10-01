package conformance

import (
	"bytes"
	"io"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/juliaogris/sallyport/conformance/testapp"
)

// TestLazyStreamSlots checks that 32 long responses at once do not make a
// 33rd request fail: it waits for a free connection or stream and
// succeeds.
func TestLazyStreamSlots(t *testing.T) {
	s := newLazyStack(t)
	cookies := s.appCookies(t, "bench")
	var wg sync.WaitGroup
	held := make([]int, 32)
	for i := range held {
		wg.Add(1)
		go func() {
			defer wg.Done()
			held[i], _ = s.timedGet(t, "/t/quiet?secs=8", cookies, 30*time.Second)
		}()
	}
	// Let the 32 reach the app before the 33rd.
	time.Sleep(2 * time.Second)
	status, took := s.timedGet(t, "/t/static", cookies, 30*time.Second)
	wg.Wait()
	t.Logf("request 33: %d after %v", status, took.Round(100*time.Millisecond))
	require.Equal(t, http.StatusOK, status, "request 33 while 32 responses were open")
	for i, st := range held {
		require.Equal(t, http.StatusOK, st, "long response %d", i)
	}
}

// TestLazyUploadsWithoutAcks checks uploads from an older callout that does
// not ask for upload acks. Without the window the hub sends as fast as it
// can, so only uploads the app reads at full speed are checked.
func TestLazyUploadsWithoutAcks(t *testing.T) {
	s := newLazyStack(t)
	s.auth.SetStreamAcks(false)
	cookies := s.appCookies(t, "bench")
	for _, size := range []int{1 << 20, 16 << 20} {
		t.Run(itoa(size>>20)+" MiB", func(t *testing.T) {
			got := s.upload(t, cookies, size, 0)
			require.Equal(t, itoa(size)+"\n", got)
		})
	}
}

// TestLazySlowUpload checks that an upload that takes longer than the
// 30 s idle close, while acks keep arriving, is not cut.
func TestLazySlowUpload(t *testing.T) {
	s := newLazyStack(t)
	cookies := s.appCookies(t, "bench")
	// 8 MiB at 200 KiB/s is about 41 s.
	got := s.upload(t, cookies, 8<<20, 200<<10)
	require.Equal(t, itoa(8<<20)+"\n", got)
}

// TestAppContentLengthAndChunked checks that a response with both
// Content-Length and Transfer-Encoding: chunked is read as chunked.
func TestAppContentLengthAndChunked(t *testing.T) {
	for _, mode := range modes {
		t.Run(mode, func(t *testing.T) {
			s := stackFor(t, mode)
			cookies := s.appCookies(t, "bench")
			resp := s.get(t, appHost("bench"), "/t/clte", cookies...)
			body, err := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Logf("status %d, %q, %v", resp.StatusCode, body, err)
			require.NoError(t, err)
			require.Equal(t, http.StatusOK, resp.StatusCode)
			require.Equal(t, "abcdefghijklmnopqrstuvwxyz", string(body))
		})
	}
}

// upload posts size bytes to bench's /t/upload, read by the app at bps
// bytes per second or at full speed with 0, and returns the app's answer.
func (s *stack) upload(t *testing.T, cookies []*http.Cookie, size, bps int) string {
	t.Helper()
	path := "/t/upload"
	if bps > 0 {
		path += "?bps=" + itoa(bps)
	}
	req, _ := http.NewRequest("POST", "https://"+appHost("bench")+path, bytes.NewReader(testapp.Pattern(size)))
	req.Header.Set("Origin", origin(appHost("bench")))
	for _, c := range cookies {
		req.AddCookie(c)
	}
	cl := s.hub.Client()
	cl.Timeout = 2 * time.Minute
	start := time.Now()
	resp, err := cl.Do(req)
	require.NoError(t, err)
	body := readBody(t, resp)
	t.Logf("%d bytes in %v: %d", size, time.Since(start).Round(100*time.Millisecond), resp.StatusCode)
	require.Equal(t, http.StatusOK, resp.StatusCode, "body %q", body)
	return string(body)
}
