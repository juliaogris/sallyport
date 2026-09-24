//! sallyport hub: a Teleport proxy for Cloudflare Workers.
//!
//! The Worker answers the unauthenticated discovery endpoint and forwards
//! agent connections to one Durable Object, which holds every tunnel.

mod app;
mod authpipe;
mod authrpc;
mod ping;
mod s5;
mod ssh;
mod tunnel;

use worker::*;

pub use tunnel::Hub;

/// The name of the single Durable Object instance that holds all state.
const HUB_INSTANCE: &str = "hub";

#[event(start)]
fn start() {
    console_error_panic_hook::set_once();
}

#[event(fetch)]
async fn fetch(req: Request, env: Env, _ctx: Context) -> Result<Response> {
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
        app::PATH | s5::PATH => {
            let ns = env.durable_object("HUB")?;
            let stub = ns.id_from_name(HUB_INSTANCE)?.get_stub()?;
            stub.fetch_with_request(req).await
        }
        _ => Response::error("not found", 404),
    }
}
