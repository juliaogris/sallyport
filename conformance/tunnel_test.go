package conformance

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

// TestTunnelSubprotocol checks that the tunnel WebSocket needs the
// alpn-ping subprotocol and answers with it.
func TestTunnelSubprotocol(t *testing.T) {
	logOnFailure(t, shared)
	t.Run("missing", func(t *testing.T) {
		ws, resp, err := shared.DialTunnelWS(t.Context())
		if ws != nil {
			ws.Close()
		}
		require.Error(t, err)
		require.NotNil(t, resp)
		require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})
	t.Run("alpn-ping", func(t *testing.T) {
		ws, _, err := shared.DialTunnelWS(t.Context(), TunnelSubprotocol)
		require.NoError(t, err)
		defer ws.Close()
		require.Equal(t, TunnelSubprotocol, ws.Subprotocol())
	})
}

// TestTunnelTLS checks the hub's TLS certificate and ALPN inside the
// tunnel WebSocket.
func TestTunnelTLS(t *testing.T) {
	logOnFailure(t, shared)
	tc, err := shared.DialTunnelTLS(t.Context(), pki)
	require.NoError(t, err)
	defer tc.Close()
	require.Equal(t, ALPNReverseTunnel, tc.ConnectionState().NegotiatedProtocol)
}

// TestTunnelAppAgent checks the hub's side of an App agent: its host
// certificate, the heartbeat, discovery, and the test dial into the
// agent.
func TestTunnelAppAgent(t *testing.T) {
	logOnFailure(t, shared)
	id, err := pki.AgentIdentity("App")
	require.NoError(t, err)
	a, err := shared.DialAgent(t.Context(), pki, id)
	require.NoError(t, err)
	defer a.Close()

	require.Contains(t, a.HostCert.ValidPrincipals, pki.HubUUID+"."+pki.Cluster)

	_, ok, err := a.Heartbeat()
	require.NoError(t, err)
	require.True(t, ok, "ping reply")

	select {
	case payload := <-a.Discovery:
		var got struct {
			Proxies []struct {
				Version  string `json:"version"`
				Metadata struct {
					Name string `json:"name"`
				} `json:"metadata"`
			} `json:"proxies"`
		}
		require.NoError(t, json.Unmarshal(payload, &got), "discovery payload %s", payload)
		require.Len(t, got.Proxies, 1)
		require.Equal(t, "v2", got.Proxies[0].Version)
		require.Equal(t, pki.HubUUID, got.Proxies[0].Metadata.Name)
	case <-time.After(10 * time.Second):
		t.Fatal("no discovery request within 10s of the first ping")
	}

	select {
	case d := <-a.Dials:
		d.Channel.Close()
		var got map[string]string
		require.NoError(t, json.Unmarshal(d.Payload, &got), "dial payload %s", d.Payload)
		require.Equal(t, map[string]string{
			"address":   AddrLocalNode,
			"server_id": id.User,
			"conn_type": "app",
		}, got)
	case <-time.After(10 * time.Second):
		t.Fatal("no test dial within 10s of the first ping")
	}

	ok, _, err = a.Conn.SendRequest("keepalive@openssh.com", true, nil)
	require.NoError(t, err)
	require.True(t, ok, "keepalive reply")
}

// TestTunnelAgentChannels checks which channels and dials the hub refuses
// from an agent.
func TestTunnelAgentChannels(t *testing.T) {
	logOnFailure(t, shared)
	app, err := pki.AgentIdentity("App")
	require.NoError(t, err)
	inst, err := pki.AgentIdentity("Instance")
	require.NoError(t, err)

	t.Run("instance heartbeat", func(t *testing.T) {
		a, err := shared.DialAgent(t.Context(), pki, inst)
		require.NoError(t, err)
		defer a.Close()
		_, _, err = a.Conn.OpenChannel(ChanHeartbeat, nil)
		requireRejected(t, err)
	})
	t.Run("session channel", func(t *testing.T) {
		a, err := shared.DialAgent(t.Context(), pki, app)
		require.NoError(t, err)
		defer a.Close()
		_, _, err = a.Conn.OpenChannel("session", nil)
		requireRejected(t, err)
	})
	for _, addr := range []string{"127.0.0.1:22", AddrLocalNode, "@remote-auth-server:3025", ""} {
		t.Run("dial "+addr, func(t *testing.T) {
			a, err := shared.DialAgent(t.Context(), pki, app)
			require.NoError(t, err)
			defer a.Close()
			ch, ok, err := a.OpenTransport(addr)
			if ch != nil {
				defer ch.Close()
			}
			if err == nil {
				require.False(t, ok, "dial to %q accepted", addr)
			}
		})
	}
}

func requireRejected(t *testing.T, err error) {
	t.Helper()
	require.Error(t, err)
	var oce *ssh.OpenChannelError
	require.ErrorAs(t, err, &oce)
}

// TestTunnelAuth checks which agent credentials the hub accepts.
func TestTunnelAuth(t *testing.T) {
	logOnFailure(t, shared)
	other, err := OtherCA()
	require.NoError(t, err)
	now := time.Now()

	type tc struct {
		name   string
		ca     ssh.Signer
		user   string
		spec   CertSpec
		accept bool
	}
	uuid := NewUUID()
	user := uuid + "." + pki.Cluster
	valid := CertSpec{Principals: []string{user, uuid}, Role: "App"}
	with := func(f func(*CertSpec)) CertSpec {
		s := valid
		s.Principals = append([]string(nil), valid.Principals...)
		f(&s)
		return s
	}
	cases := []tc{
		{name: "app", ca: pki.HostCA, user: user, spec: valid, accept: true},
		{name: "instance", ca: pki.HostCA, user: user, spec: with(func(s *CertSpec) { s.Role = "Instance" }), accept: true},
		{name: "plain key", ca: pki.HostCA, user: user},
		{name: "user certificate", ca: pki.HostCA, user: user, spec: with(func(s *CertSpec) { s.CertType = ssh.UserCert })},
		{name: "other CA", ca: other, user: user, spec: valid},
		{name: "user not a principal", ca: pki.HostCA, user: NewUUID() + "." + pki.Cluster, spec: valid},
		{name: "other cluster", ca: pki.HostCA, user: user, spec: with(func(s *CertSpec) { s.Authority = "other" })},
		{name: "role Node", ca: pki.HostCA, user: user, spec: with(func(s *CertSpec) { s.Role = "Node" })},
		{name: "role Proxy", ca: pki.HostCA, user: user, spec: with(func(s *CertSpec) { s.Role = "Proxy" })},
		{name: "no role", ca: pki.HostCA, user: user, spec: with(func(s *CertSpec) { s.Role = "" })},
		{name: "expired", ca: pki.HostCA, user: user, spec: with(func(s *CertSpec) {
			s.ValidAfter, s.ValidBefore = now.Add(-2*time.Hour), now.Add(-time.Hour)
		})},
		{name: "not yet valid", ca: pki.HostCA, user: user, spec: with(func(s *CertSpec) {
			s.ValidAfter, s.ValidBefore = now.Add(time.Hour), now.Add(2*time.Hour)
		})},
	}
	for _, c := range cases {
		t.Run(strings.ReplaceAll(c.name, " ", "_"), func(t *testing.T) {
			var spec CertSpec
			if c.name != "plain key" {
				spec = c.spec
			}
			id, err := pki.NewIdentity(c.ca, c.user, spec)
			require.NoError(t, err)
			a, err := shared.DialAgent(t.Context(), pki, id)
			if c.accept {
				require.NoError(t, err)
				a.Close()
				return
			}
			if a != nil {
				a.Close()
			}
			require.Error(t, err)
			require.Contains(t, err.Error(), "unable to authenticate")
		})
	}
}
