//! S5 only: `/spike/s5` runs the hub's calls to auth over two auth pipe
//! streams and answers with what came back. Off unless `DEV_S5` is "1".
//!
//! 1. With the hub TLS identity: `Ping` and `GetClusterName`.
//! 2. With the user's cert in `S5_USER_CERT` and `S5_USER_KEY`:
//!    `CreateAppSession` for the app `S5_APP_NAME` at `S5_APP_HOST`.
//! 3. With the hub TLS identity: `GetAppSession` for that session, which
//!    returns the session's cert and key.

use std::sync::Arc;

use serde_json::json;
use worker::*;

use crate::authpipe::Pool;
use crate::authrpc::{self, *};

pub const PATH: &str = "/spike/s5";

pub async fn handle(env: &Env, pool: &Pool) -> Result<Response> {
    let enabled = env.var("DEV_S5").map(|v| v.to_string() == "1").unwrap_or(false);
    if !enabled {
        return Response::error("not found", 404);
    }
    match run(env, pool).await {
        Ok(v) => Response::from_json(&v),
        Err(err) => {
            console_error!("s5: {err}");
            Response::error(err, 502)
        }
    }
}

async fn run(env: &Env, pool: &Pool) -> std::result::Result<serde_json::Value, String> {
    let e = |err: Error| err.to_string();
    let hub_tls = Arc::new(authrpc::tls_config(env, "HUB_TLS_CERT", "HUB_TLS_KEY").map_err(e)?);
    let user_tls = Arc::new(authrpc::tls_config(env, "S5_USER_CERT", "S5_USER_KEY").map_err(e)?);
    let ready_before = pool.ready();

    let start = Date::now().as_millis();
    let hub = authrpc::connect(pool.take().ok_or("no auth pipe stream")?, hub_tls).await?;
    let connected = Date::now().as_millis();
    let ping: PingResponse = unary(&hub, PING, &PingRequest {}).await?;
    let pinged = Date::now().as_millis();
    let name: ClusterNameV2 = unary(&hub, GET_CLUSTER_NAME, &GetClusterNameRequest {}).await?;

    let user = authrpc::connect(pool.take().ok_or("no second auth pipe stream")?, user_tls).await?;
    let created: SessionResponse = unary(
        &user,
        CREATE_APP_SESSION,
        &CreateAppSessionRequest {
            username: env.var("S5_USER").map_err(e)?.to_string(),
            public_addr: env.var("S5_APP_HOST").map_err(e)?.to_string(),
            cluster_name: ping.cluster_name.clone(),
            app_name: env.var("S5_APP_NAME").map_err(e)?.to_string(),
        },
    )
    .await?;
    let session_id = created
        .session
        .and_then(|s| s.metadata)
        .map(|m| m.name)
        .ok_or("CreateAppSession returned no session name")?;

    let got: SessionResponse = unary(&hub, GET_APP_SESSION, &GetAppSessionRequest { session_id: session_id.clone() }).await?;
    let spec = got.session.and_then(|s| s.spec).ok_or("GetAppSession returned no spec")?;
    let done = Date::now().as_millis();

    console_log!("s5: ping {:?}, app session for {:?} with a {}-byte cert", ping.cluster_name, spec.user, spec.tls_cert.len());
    Ok(json!({
        "ping": { "cluster_name": ping.cluster_name, "server_version": ping.server_version },
        "cluster_name": name.spec.map(|s| s.cluster_name),
        "app_session": {
            "id_len": session_id.len(),
            "user": spec.user,
            "tls_cert_bytes": spec.tls_cert.len(),
            "has_tls_private_key": !spec.tls_priv.is_empty() || !spec.priv_key.is_empty(),
        },
        "streams_ready_before": ready_before,
        "streams_ready_after": pool.ready(),
        "connect_ms": connected - start,
        "ping_ms": pinged - connected,
        "total_ms": done - start,
    }))
}
