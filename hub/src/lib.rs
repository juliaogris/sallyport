//! sallyport hub: a Teleport proxy for Cloudflare Workers.
//!
//! The Worker answers the unauthenticated discovery endpoint and forwards
//! agent connections to one Durable Object, which holds every tunnel.

mod app;
mod appproxy;
mod authpipe;
mod authrpc;
mod ping;
#[cfg(feature = "spikes")]
mod s4;
#[cfg(feature = "spikes")]
mod s5;
#[cfg(feature = "spikes")]
mod s5login;
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
    // Every path on an app host is app traffic, so it goes to the hub.
    if matches!(kind, Some(web::Host::App(_))) {
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
            let ns = env.durable_object("HUB")?;
            let stub = ns.id_from_name(HUB_INSTANCE)?.get_stub()?;
            stub.fetch_with_request(req).await
        }
        #[cfg(feature = "spikes")]
        p if p.starts_with("/spike/") => hub(&env)?.fetch_with_request(req).await,
        _ if kind.is_some() => hub(&env)?.fetch_with_request(req).await,
        _ => Response::error("not found", 404),
    }
}

/// Returns the stub of the single Durable Object that holds all state.
fn hub(env: &Env) -> Result<Stub> {
    env.durable_object("HUB")?.id_from_name(HUB_INSTANCE)?.get_stub()
}
