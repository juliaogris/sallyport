//! Forwards one browser HTTP request to a Teleport app service.
//!
//! The hub dials the app service through the agent tunnel with
//! `crate::app::dial_app`, then runs hyper's HTTP/1.1 client over the TLS
//! stream. The response streams back to the browser as it arrives, instead
//! of buffering the whole body in memory.

use std::cell::Cell;
use std::pin::Pin;
use std::rc::{Rc, Weak};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
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
const HOP_BY_HOP: &[&str] = &["connection", "keep-alive", "proxy-connection", "transfer-encoding", "te", "trailer", "upgrade"];

/// The prefix of the session cookies the hub itself sets. The app service
/// never needs to see them, so they are stripped from the `Cookie` header
/// before the request goes upstream.
const SP_COOKIE_PREFIX: &str = "__Host-sp_";

/// How long a response body may wait for the runtime to pull the next
/// chunk before the hub closes the app service connection. When the
/// browser goes away, the runtime stops pulling but does not always cancel
/// the stream, and the connection and its channel would stay open.
const STREAM_IDLE: Duration = Duration::from_secs(30);

/// Sends one HTTP request to the app service at `host` through the agent
/// tunnel, and returns the app service's response.
///
/// `tls` is the client identity to present, built with
/// `crate::authrpc::client_tls`.
/// `cluster` picks the SNI the app service expects. The request body and
/// the response body both stream as they arrive.
///
/// On a dial, TLS or HTTP/1.1 handshake failure, or an error from the app
/// service's connection, this logs the error and returns a 502 "app
/// unavailable" response.
pub async fn forward(tunnel: &AppTunnel, tls: Arc<rustls::ClientConfig>, cluster: &str, host: &str, mut req: Request) -> Result<Response> {
    match forward_inner(tunnel, tls, cluster, host, &mut req).await {
        Ok(resp) => Ok(resp),
        Err(err) => {
            console_error!("appproxy: {err}");
            Response::error("app unavailable", 502)
        }
    }
}

async fn forward_inner(tunnel: &AppTunnel, tls: Arc<rustls::ClientConfig>, cluster: &str, host: &str, req: &mut Request) -> std::result::Result<Response, String> {
    let stream = dial_app(tunnel, tls, cluster).await?;
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

    let request = build_request(req, host).await?;
    let response = send.send_request(request).await.map_err(|e| format!("app request: {e}"))?;
    build_response(response, abort)
}

/// Builds the request the hub sends upstream: `req`'s method and path, its
/// headers with the hop-by-hop, `Host` and `cf-*` ones dropped, `Host` set
/// to `host`, and the hub's own session cookies removed from `Cookie`.
async fn build_request(req: &mut Request, host: &str) -> std::result::Result<http::Request<RequestBody>, String> {
    let method = req.method();
    let url = req.url().map_err(|e| format!("request url: {e}"))?;
    let mut target = url.path().to_string();
    if let Some(query) = url.query() {
        target.push('?');
        target.push_str(query);
    }

    let mut builder = http::Request::builder()
        .method(http::Method::from_bytes(method.as_ref().as_bytes()).map_err(|e| format!("method {method}: {e}"))?)
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
        Either::Right(StreamBody::new(stream.map(|chunk| chunk.map(|b| Frame::data(Bytes::from(b))).map_err(|e| std::io::Error::other(e.to_string()))).boxed_local()))
    };
    builder.body(body).map_err(|e| format!("build request: {e}"))
}

/// The body of a request to the app service: empty, or the browser's body
/// as it arrives.
type RequestBody = Either<Empty<Bytes>, StreamBody<LocalBoxStream<'static, std::result::Result<Frame<Bytes>, std::io::Error>>>>;

/// Removes every cookie whose name starts with [`SP_COOKIE_PREFIX`] from a
/// `Cookie` header value. Returns `None` when nothing is left to send.
fn strip_sp_cookies(value: &str) -> Option<String> {
    let kept: Vec<&str> = value.split(';').map(str::trim).filter(|c| !c.is_empty() && !c.starts_with(SP_COOKIE_PREFIX)).collect();
    if kept.is_empty() { None } else { Some(kept.join("; ")) }
}

/// Turns the app service's HTTP/1.1 response into a `worker::Response`,
/// with the hop-by-hop headers dropped and the body streamed as it arrives.
/// `conn` aborts the app service connection when the body is idle for
/// [`STREAM_IDLE`].
fn build_response(response: http::Response<hyper::body::Incoming>, conn: AbortHandle) -> std::result::Result<Response, String> {
    let (parts, incoming) = response.into_parts();
    if parts.status.is_server_error() {
        console_error!("appproxy: upstream {} {:?}", parts.status, parts.headers.get(http::header::SERVER));
    }
    let headers = Headers::new();
    for (name, value) in parts.headers.iter() {
        if HOP_BY_HOP.contains(&name.as_str()) {
            continue;
        }
        let value = value.to_str().map_err(|e| format!("response header {name}: {e}"))?;
        // The app must not replace or clear the hub's own session cookies.
        if name == http::header::SET_COOKIE && value.trim_start().starts_with(SP_COOKIE_PREFIX) {
            continue;
        }
        headers.append(name.as_str(), value).map_err(|e| format!("response header {name}: {e}"))?;
    }
    // The runtime refuses a body on these statuses, and workers-rs panics
    // on that refusal, which restarts the Durable Object.
    let status = parts.status.as_u16();
    if matches!(status, 101 | 204 | 205 | 304) {
        let res = Response::empty().map_err(|e| format!("response: {e}"))?;
        return Ok(res.with_headers(headers).with_status(status));
    }
    let mut body = Response::from_stream(body_stream(incoming, conn)).map_err(|e| format!("response body: {e}"))?;
    // The runtime compresses a body to match `Content-Encoding` by
    // default, so an app's gzipped body would be compressed twice.
    if parts.headers.contains_key(http::header::CONTENT_ENCODING) {
        body = body.with_encode_body(EncodeBody::Manual);
    }
    Ok(body.with_headers(headers).with_status(status))
}

/// Turns a hyper `Incoming` body into the byte stream `Response::from_stream`
/// wants, keeping only the data frames and skipping any trailers. When the
/// runtime does not pull the next chunk for [`STREAM_IDLE`], it aborts
/// `conn`.
fn body_stream(incoming: hyper::body::Incoming, conn: AbortHandle) -> impl futures::Stream<Item = std::result::Result<Vec<u8>, Error>> + 'static {
    // The time the stream last handed a chunk to the runtime, or None while
    // the stream waits on the app service. Only the wait for a pull counts,
    // not a slow app service.
    let pulled: Rc<Cell<Option<u64>>> = Rc::new(Cell::new(None));
    wasm_bindgen_futures::spawn_local(end_when_idle(Rc::downgrade(&pulled), conn));
    futures::stream::unfold((incoming, pulled), |(mut incoming, pulled)| async move {
        pulled.set(None);
        loop {
            match incoming.frame().await {
                None => return None,
                Some(Err(err)) => {
                    console_error!("appproxy: response body: {err}");
                    return Some((Err(Error::RustError(err.to_string())), (incoming, pulled)));
                }
                Some(Ok(frame)) => match frame.into_data() {
                    Ok(data) => {
                        pulled.set(Some(Date::now().as_millis()));
                        return Some((Ok(data.to_vec()), (incoming, pulled)));
                    }
                    // A trailers frame, which HTTP/1.1 responses rarely
                    // carry. Keep reading for the real end of the body.
                    Err(_) => continue,
                },
            }
        }
    })
}

/// Aborts `conn` once `pulled` shows no pull for [`STREAM_IDLE`]. It returns
/// when the body stream that owns `pulled` is dropped.
async fn end_when_idle(pulled: Weak<Cell<Option<u64>>>, conn: AbortHandle) {
    let idle_ms = STREAM_IDLE.as_millis() as u64;
    let mut wait = STREAM_IDLE;
    loop {
        crate::sockets::sleep(wait).await;
        let Some(pulled) = pulled.upgrade() else {
            return;
        };
        wait = STREAM_IDLE;
        if let Some(at) = pulled.get() {
            let waited = Date::now().as_millis().saturating_sub(at);
            if waited >= idle_ms {
                console_log!("appproxy: response body not read for {STREAM_IDLE:?}, closing");
                conn.abort();
                return;
            }
            wait = Duration::from_millis(idle_ms - waited);
        }
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
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, mut buf: hyper::rt::ReadBufCursor<'_>) -> Poll<std::io::Result<()>> {
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
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
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
        assert_eq!(strip_sp_cookies("__Host-sp_app=s; __Host-sp_subject=t"), None);
        assert_eq!(strip_sp_cookies("a=1; __Host-sp_subject=t; b=2"), Some("a=1; b=2".into()));
        assert_eq!(strip_sp_cookies("a=1;; ;b=2"), Some("a=1; b=2".into()));
        assert_eq!(strip_sp_cookies(""), None);
    }
}
