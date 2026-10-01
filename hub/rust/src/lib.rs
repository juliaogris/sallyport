//! sallyport hub: a Teleport proxy for Cloudflare Workers.
//!
//! The Worker answers the unauthenticated discovery endpoint and the
//! requests in [`web::answer_without_hub`], and forwards everything else to
//! one Durable Object, which holds every tunnel.

mod app;
mod appproxy;
mod authpipe;
mod authrpc;
mod lazy;
mod passkeys;
mod ping;
mod sockets;
mod ssh;
mod tunnel;
mod web;
mod wsevents;

use worker::*;

pub use tunnel::Hub;

/// The name of the single Durable Object instance that holds all state.
const HUB_INSTANCE: &str = "hub";

#[event(start)]
fn start() {
    std::panic::set_hook(Box::new(|info| {
        console_error_panic_hook::hook(info);
        sockets::set_last_panic(&info.to_string());
    }));
}

#[event(fetch)]
async fn fetch(req: Request, env: Env, _ctx: Context) -> Result<Response> {
    let host = req.url()?.host_str().unwrap_or_default().to_string();
    let kind = web::classify(&env, &host);
    // Every path on an app host is app traffic, so it goes to the hub,
    // unless the hub's answer needs no session.
    if let Some(app @ web::Host::App(_)) = &kind {
        if let Some(res) = web::answer_without_hub(&req, &env, app)? {
            return Ok(res);
        }
        return hub(&env)?.fetch_with_request(req).await;
    }
    let path = req.path();
    match path.as_str() {
        "/webapi/find" | "/webapi/ping" => ping::handle(&env),
        "/webapi/connectionupgrade" | authpipe::PATH => {
            // Reject before waking the Durable Object when the request is
            // not a WebSocket upgrade at all.
            let upgrade = req.headers().get("Upgrade")?.unwrap_or_default();
            if !upgrade.eq_ignore_ascii_case("websocket") {
                return Response::error("upgrade required", 426);
            }
            // The lazy hub has no reverse tunnel, and an agent that dials it
            // anyway retries, so it must not wake the Durable Object each
            // time.
            if path == "/webapi/connectionupgrade" && lazy::enabled(&env) {
                return Response::error("not found", 404);
            }
            hub(&env)?.fetch_with_request(req).await
        }
        _ if kind.is_some() => {
            if let Some(res) = web::answer_without_hub(&req, &env, &web::Host::Login)? {
                return Ok(res);
            }
            hub(&env)?.fetch_with_request(req).await
        }
        _ => Response::error("not found", 404),
    }
}

/// Returns the stub of the single Durable Object that holds all state.
fn hub(env: &Env) -> Result<Stub> {
    env.durable_object("HUB")?
        .id_from_name(HUB_INSTANCE)?
        .get_stub()
}
