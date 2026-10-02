package conformance

import (
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestAuthCallDeadline checks that an auth call that runs past the hub's
// 5 s call deadline fails only that request: it gets a 5xx, and the next
// requests work. The hub gives up on the call while its HTTP/2 stream is
// still open, which resets the stream.
func TestAuthCallDeadline(t *testing.T) {
	for _, mode := range modes {
		t.Run(mode, func(t *testing.T) {
			s := stackFor(t, mode)
			cookies := s.appCookies(t, "bench")
			s.auth.SetDelay("GetAppSession", 8*time.Second)
			status, took := s.timedGet(t, "/t/static", cookies, 30*time.Second)
			s.auth.SetDelay("GetAppSession", 0)
			t.Logf("slow call: %d after %v", status, took.Round(100*time.Millisecond))
			require.GreaterOrEqual(t, status, 500)
			// The Go hub retries a call that failed at the transport once, so
			// the answer can take two call deadlines.
			require.Less(t, took, 15*time.Second, "no answer within two call deadlines")

			for i := range 5 {
				status, _ := s.timedGet(t, "/t/static", cookies, 20*time.Second)
				require.Equal(t, http.StatusOK, status, "request %d after the slow call", i)
			}
			require.False(t, s.hub.LogHas("previous WASM instance"), "the hub's wasm instance was replaced")
			require.False(t, s.hub.LogHas("panicked"), "the hub panicked")
		})
	}
}
