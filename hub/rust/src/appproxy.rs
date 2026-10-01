//! Forwards one browser HTTP request to a Teleport app service.
//!
//! The hub dials the app service through the agent tunnel with
//! `crate::app::dial_app`, or through auth's on-demand callout with
//! `crate::app::dial_app_lazy`, then runs hyper's HTTP/1.1 client over the
//! TLS stream. The response streams back to the browser as it arrives, instead
//! of buffering the whole body in memory.

use std::cell::Cell;
use std::pin::Pin;
use std::rc::Rc;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use futures::channel::oneshot;
use futures::future::{abortable, AbortHandle};
use futures::stream::LocalBoxStream;
use futures::StreamExt;
use http_body_util::{BodyExt, Either, Empty, StreamBody};
use hyper::body::Frame;
use worker::*;

use crate::app::dial_app;
use crate::ssh::AppTunnel;

/// Header names that describe one hop of the connection, per RFC 7230 6.1,
/// plus the handful browsers and proxies add in practice. None of these are
/// forwarded in either direction.
const HOP_BY_HOP: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-connection",
    "transfer-encoding",
    "te",
    "trailer",
    "upgrade",
];

/// The prefix of the session cookies the hub itself sets. The app service
/// never needs to see them, so they are stripped from the `Cookie` header
/// before the request goes upstream.
const SP_COOKIE_PREFIX: &str = "__Host-sp_";

/// How long a response body may go without passing a chunk to the runtime
/// before the hub closes the app service connection and ends the body with
/// an error. The wait counts both a silent app and a runtime that does not
/// pull. When the browser goes away, the runtime stops pulling but does not
/// always cancel the stream, and the connection and its channel would stay
/// open. This also ends an app response that sends nothing for that long,
/// as the lazy hub's stream idle does.
const STREAM_IDLE: Duration = Duration::from_secs(30);

/// Where an app connection comes from: the agent's tunnel, or auth's
/// on-demand callout in the lazy hub.
pub enum AppDialer<'a> {
    Tunnel(&'a AppTunnel),
    Lazy(std::rc::Rc<crate::lazy::Lazy>),
}

/// Sends one HTTP request to the app service at `host` through the agent
/// tunnel or auth's on-demand callout, and returns the app service's
/// response.
///
/// `tls` is the client identity to present, built with
/// `crate::authrpc::client_tls`.
/// `cluster` picks the SNI the app service expects. The request body and
/// the response body both stream as they arrive.
///
/// On a dial, TLS or HTTP/1.1 handshake failure, or an error from the app
/// service's connection, this logs the error and returns a 502 "app
/// unavailable" response. When the lazy hub has no room for the dial, it
/// returns a 503 "app service busy" response.
pub async fn forward(
    tunnel: AppDialer<'_>,
    tls: Arc<rustls::ClientConfig>,
    cluster: &str,
    host: &str,
    mut req: Request,
) -> Result<Response> {
    let stream = match tunnel {
        AppDialer::Tunnel(t) => dial_app(t, tls, cluster).await,
        AppDialer::Lazy(l) => match crate::app::dial_app_lazy(&l, tls, cluster).await {
            Err(crate::lazy::DialError::Busy(err)) => {
                console_error!("appproxy: {err}");
                return Response::error("app service busy", 503);
            }
            res => res.map_err(|e| e.to_string()),
        },
    };
    let res = match stream {
        Ok(stream) => forward_inner(stream, host, &mut req).await,
        Err(err) => Err(err),
    };
    match res {
        Ok(resp) => Ok(resp),
        Err(err) => {
            console_error!("appproxy: {err}");
            Response::error("app unavailable", 502)
        }
    }
}

async fn forward_inner(
    stream: crate::app::AppStream,
    host: &str,
    req: &mut Request,
) -> std::result::Result<Response, String> {
    let (mut send, conn) = hyper::client::conn::http1::handshake(HyperIo::new(stream))
        .await
        .map_err(|e| format!("http1 handshake: {e}"))?;
    // The connection future drives the socket. Nothing here polls it again,
    // so it must run on its own for `send` to make progress. Aborting it
    // drops the TLS stream, which closes the channel.
    let (conn, abort) = abortable(conn);
    wasm_bindgen_futures::spawn_local(async move {
        if let Ok(Err(err)) = conn.await {
            console_log!("appproxy: connection ended: {err}");
        }
    });

    let head = req.method() == Method::Head;
    let request = build_request(req, host)?;
    let response = send
        .send_request(request)
        .await
        .map_err(|e| format!("app request: {e}"))?;
    build_response(response, abort, head)
}

/// Builds the request the hub sends upstream: `req`'s method and path, its
/// headers with the hop-by-hop, `Host` and `cf-*` ones dropped, `Host` set
/// to `host`, and the hub's own session cookies removed from `Cookie`.
fn build_request(
    req: &mut Request,
    host: &str,
) -> std::result::Result<http::Request<RequestBody>, String> {
    let method = req.method();
    let url = req.url().map_err(|e| format!("request url: {e}"))?;
    let mut target = url.path().to_string();
    if let Some(query) = url.query() {
        target.push('?');
        target.push_str(query);
    }

    let mut builder = http::Request::builder()
        .method(
            http::Method::from_bytes(method.as_ref().as_bytes())
                .map_err(|e| format!("method {method}: {e}"))?,
        )
        .uri(target);
    for (name, value) in req.headers().entries() {
        if name == "host" || name.starts_with("cf-") || HOP_BY_HOP.contains(&name.as_str()) {
            continue;
        }
        if name == "cookie" {
            if let Some(kept) = strip_sp_cookies(&value) {
                builder = builder.header("cookie", kept);
            }
            continue;
        }
        builder = builder.header(name, value);
    }
    builder = builder.header("host", host);

    // The body streams, so an upload is never held whole in Wasm memory.
    // The browser's `Content-Length` is kept, and hyper sends that many
    // bytes.
    let body = if matches!(method, Method::Get | Method::Head) || req.inner().body().is_none() {
        Either::Left(Empty::new())
    } else {
        let stream = req.stream().map_err(|e| format!("request body: {e}"))?;
        Either::Right(StreamBody::new(
            stream
                .map(|chunk| {
                    chunk
                        .map(|b| Frame::data(Bytes::from(b)))
                        .map_err(|e| std::io::Error::other(e.to_string()))
                })
                .boxed_local(),
        ))
    };
    builder
        .body(body)
        .map_err(|e| format!("build request: {e}"))
}

/// The body of a request to the app service: empty, or the browser's body
/// as it arrives.
type RequestBody = Either<
    Empty<Bytes>,
    StreamBody<LocalBoxStream<'static, std::result::Result<Frame<Bytes>, std::io::Error>>>,
>;

/// Removes every cookie whose name starts with [`SP_COOKIE_PREFIX`] from a
/// `Cookie` header value. Returns `None` when nothing is left to send.
fn strip_sp_cookies(value: &str) -> Option<String> {
    let kept: Vec<&str> = value
        .split(';')
        .map(str::trim)
        .filter(|c| !c.is_empty() && !c.starts_with(SP_COOKIE_PREFIX))
        .collect();
    if kept.is_empty() {
        None
    } else {
        Some(kept.join("; "))
    }
}

/// Turns the app service's HTTP/1.1 response into a `worker::Response`,
/// with the hop-by-hop headers dropped and the body streamed as it arrives.
/// `conn` aborts the app service connection when the body is idle for
/// [`STREAM_IDLE`]. `head` is true for the response to a HEAD request, whose
/// `Content-Length` counts no body.
fn build_response(
    response: http::Response<hyper::body::Incoming>,
    conn: AbortHandle,
    head: bool,
) -> std::result::Result<Response, String> {
    let (parts, incoming) = response.into_parts();
    if parts.status.is_server_error() {
        console_error!(
            "appproxy: upstream {} {:?}",
            parts.status,
            parts.headers.get(http::header::SERVER)
        );
    }
    let headers = Headers::new();
    for (name, value) in parts.headers.iter() {
        if HOP_BY_HOP.contains(&name.as_str()) {
            continue;
        }
        let value = value
            .to_str()
            .map_err(|e| format!("response header {name}: {e}"))?;
        // The app must not replace or clear the hub's own session cookies.
        if name == http::header::SET_COOKIE && value.trim_start().starts_with(SP_COOKIE_PREFIX) {
            continue;
        }
        headers
            .append(name.as_str(), value)
            .map_err(|e| format!("response header {name}: {e}"))?;
    }
    // The runtime accepts a 101 only with a WebSocket attached, and the hub
    // sends no Upgrade header upstream, so a 101 cannot be forwarded. The
    // app connection is closed, because it no longer speaks HTTP.
    let status = parts.status.as_u16();
    if status == 101 {
        conn.abort();
        console_error!("appproxy: app answered 101 Switching Protocols");
        return Response::error("app answered 101 Switching Protocols", 502)
            .map_err(|e| format!("response: {e}"));
    }
    // The runtime refuses a body on these statuses, and workers-rs panics
    // on that refusal, which restarts the Durable Object.
    if matches!(status, 204 | 205 | 304) {
        let res = Response::empty().map_err(|e| format!("response: {e}"))?;
        return Ok(res.with_headers(headers).with_status(status));
    }
    let want = parts
        .headers
        .get(http::header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok()?.parse::<u64>().ok())
        .filter(|_| !head);
    let mut body = Response::from_stream(body_stream(incoming, conn, want))
        .map_err(|e| format!("response body: {e}"))?;
    // The runtime compresses a body to match `Content-Encoding` by
    // default, so an app's gzipped body would be compressed twice.
    if parts.headers.contains_key(http::header::CONTENT_ENCODING) {
        body = body.with_encode_body(EncodeBody::Manual);
    }
    Ok(body.with_headers(headers).with_status(status))
}

/// Turns a hyper `Incoming` body into the byte stream `Response::from_stream`
/// wants, keeping only the data frames and skipping any trailers. When no
/// chunk has gone to the runtime for [`STREAM_IDLE`], it aborts `conn`. A
/// body that ends at that abort, or before `want` bytes, the response's
/// `Content-Length`, ends with an error, so that the browser does not take
/// the part it got for the whole body.
fn body_stream(
    incoming: hyper::body::Incoming,
    conn: AbortHandle,
    want: Option<u64>,
) -> impl futures::Stream<Item = std::result::Result<Vec<u8>, Error>> + 'static {
    // The time the stream last handed a chunk to the runtime. The clock
    // starts before the first pull, so a body the runtime never pulls is
    // aborted too.
    let last = Rc::new(Cell::new(Date::now().as_millis()));
    // True once the idle task has aborted `conn`.
    let cut = Rc::new(Cell::new(false));
    // The stream holds `done`, so dropping the stream ends the idle task.
    let (done, done_rx) = oneshot::channel::<()>();
    wasm_bindgen_futures::spawn_local(end_when_idle(last.clone(), cut.clone(), done_rx, conn));
    let state = BodyState {
        incoming,
        last,
        cut,
        got: 0,
        _done: done,
    };
    // The state is None once the stream has sent its error.
    futures::stream::unfold(Some(state), move |state| async move {
        let mut st = state?;
        loop {
            match st.incoming.frame().await {
                None => {
                    let msg = if st.cut.get() {
                        format!("no bytes for {STREAM_IDLE:?}")
                    } else {
                        match want {
                            Some(w) if st.got < w => format!("ended after {} of {w} bytes", st.got),
                            _ => return None,
                        }
                    };
                    console_error!("appproxy: response body: {msg}");
                    return Some((Err(Error::RustError(msg)), None));
                }
                Some(Err(err)) => {
                    console_error!("appproxy: response body: {err}");
                    return Some((Err(Error::RustError(err.to_string())), None));
                }
                Some(Ok(frame)) => match frame.into_data() {
                    Ok(data) => {
                        st.got += data.len() as u64;
                        st.last.set(Date::now().as_millis());
                        return Some((Ok(data.to_vec()), Some(st)));
                    }
                    // A trailers frame, which HTTP/1.1 responses rarely
                    // carry. Keep reading for the real end of the body.
                    Err(_) => continue,
                },
            }
        }
    })
}

/// The state of a [`body_stream`].
struct BodyState {
    incoming: hyper::body::Incoming,
    last: Rc<Cell<u64>>,
    cut: Rc<Cell<bool>>,
    /// The body bytes passed on.
    got: u64,
    /// Ends [`end_when_idle`] when the stream is dropped.
    _done: oneshot::Sender<()>,
}

/// Aborts `conn` and sets `cut` once `last` is [`STREAM_IDLE`] old. It
/// returns when `done` resolves, which is when the body stream is dropped.
async fn end_when_idle(
    last: Rc<Cell<u64>>,
    cut: Rc<Cell<bool>>,
    mut done: oneshot::Receiver<()>,
    conn: AbortHandle,
) {
    let idle_ms = STREAM_IDLE.as_millis() as u64;
    let mut wait = STREAM_IDLE;
    loop {
        let sleep = std::pin::pin!(crate::sockets::sleep(wait));
        if let futures::future::Either::Right(_) = futures::future::select(sleep, &mut done).await {
            return;
        }
        let waited = Date::now().as_millis().saturating_sub(last.get());
        if waited >= idle_ms {
            console_log!("appproxy: response body idle for {STREAM_IDLE:?}, closing");
            cut.set(true);
            conn.abort();
            return;
        }
        wait = Duration::from_millis(idle_ms - waited);
    }
}

/// Adapts a tokio `AsyncRead + AsyncWrite` stream to hyper 1.x's own `Read`
/// and `Write` traits, so the app TLS stream can drive a hyper client
/// without pulling in hyper-util for its `TokioIo` wrapper.
struct HyperIo<T> {
    inner: T,
}

impl<T> HyperIo<T> {
    fn new(inner: T) -> Self {
        Self { inner }
    }
}

impl<T: tokio::io::AsyncRead + Unpin> hyper::rt::Read for HyperIo<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        mut buf: hyper::rt::ReadBufCursor<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        // SAFETY: `read_buf` only wraps the uninitialized memory `buf`
        // already lent us, and it is never read before `poll_read` fills it.
        let mut read_buf = tokio::io::ReadBuf::uninit(unsafe { buf.as_mut() });
        match Pin::new(&mut this.inner).poll_read(cx, &mut read_buf) {
            Poll::Ready(Ok(())) => {
                let n = read_buf.filled().len();
                // SAFETY: `poll_read` reports exactly `n` bytes filled, into
                // the same memory `buf` handed to `read_buf` above.
                unsafe { buf.advance(n) };
                Poll::Ready(Ok(()))
            }
            other => other,
        }
    }
}

impl<T: tokio::io::AsyncWrite + Unpin> hyper::rt::Write for HyperIo<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strip_sp_cookies_cases() {
        assert_eq!(
            strip_sp_cookies("__Host-sp_app=s; __Host-sp_subject=t"),
            None
        );
        assert_eq!(
            strip_sp_cookies("a=1; __Host-sp_subject=t; b=2"),
            Some("a=1; b=2".into())
        );
        assert_eq!(strip_sp_cookies("a=1;; ;b=2"), Some("a=1; b=2".into()));
        assert_eq!(strip_sp_cookies(""), None);
    }
}
