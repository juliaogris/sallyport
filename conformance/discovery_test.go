package conformance

import (
	"io"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestDiscovery checks /webapi/find and /webapi/ping, which a stock agent
// reads to pick TLS routing and the tunnel address.
func TestDiscovery(t *testing.T) {
	logOnFailure(t, shared)
	want := `{
		"cluster_name": "sallyport-test",
		"edition": "oss",
		"min_client_version": "17.0.0-aa",
		"proxy": {
			"ssh": {
				"listen_addr": "hub.test:443",
				"public_addr": "hub.test:443",
				"web_listen_addr": "hub.test:443"
			},
			"tls_routing_enabled": true
		},
		"server_version": "18.11.1"
	}`
	for _, path := range []string{"/webapi/find", "/webapi/ping"} {
		t.Run(path, func(t *testing.T) {
			resp, err := shared.Get(LoginHost, path)
			require.NoError(t, err)
			defer resp.Body.Close()
			body, err := io.ReadAll(resp.Body)
			require.NoError(t, err)
			require.Equal(t, http.StatusOK, resp.StatusCode)
			require.Contains(t, resp.Header.Get("Content-Type"), "application/json")
			require.JSONEq(t, want, string(body))
		})
	}
}

// TestUpgradeRequired checks that the upgrade paths refuse a request that
// is not a WebSocket upgrade.
func TestUpgradeRequired(t *testing.T) {
	logOnFailure(t, shared)
	for _, path := range []string{TunnelPath, CalloutPath} {
		t.Run(path, func(t *testing.T) {
			resp, err := shared.Get(LoginHost, path)
			require.NoError(t, err)
			resp.Body.Close()
			require.Equal(t, http.StatusUpgradeRequired, resp.StatusCode)
		})
	}
}

// TestUnknownHost checks that a host that is neither the login host nor an
// app host gets 404.
func TestUnknownHost(t *testing.T) {
	logOnFailure(t, shared)
	for _, host := range []string{"other.test", "hub.example", "-hub.test", "bench_x-hub.test", ".hub.test", "bench.hub.test"} {
		t.Run(host, func(t *testing.T) {
			resp, err := shared.Get(host, "/")
			require.NoError(t, err)
			resp.Body.Close()
			require.Equal(t, http.StatusNotFound, resp.StatusCode)
		})
	}
}
