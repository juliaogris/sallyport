//! The `/webapi/find` response a stock agent needs to pick TLS routing and
//! the tunnel address.

use serde_json::json;
use worker::*;

pub fn handle(env: &Env) -> Result<Response> {
    let cluster = env.var("CLUSTER_NAME")?.to_string();
    let public_addr = env.var("PUBLIC_ADDR")?.to_string();
    let version = env.var("SERVER_VERSION")?.to_string();
    // The agent reads `proxy.tls_routing_enabled` to choose multiplex mode
    // and `proxy.ssh.public_addr` as the tunnel address
    // (api/client/webclient/webclient.go, tunnelProxyAddr).
    Response::from_json(&json!({
        "proxy": {
            "tls_routing_enabled": true,
            "ssh": {
                "public_addr": public_addr,
                "listen_addr": public_addr,
                "web_listen_addr": public_addr,
            },
        },
        "server_version": version,
        "min_client_version": "17.0.0-aa",
        "cluster_name": cluster,
        "edition": "oss",
    }))
}
