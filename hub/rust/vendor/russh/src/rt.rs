//! Time primitives for the server path.
//!
//! On native targets these are tokio's. On `wasm32` there is no tokio timer
//! driver and `std::time::Instant::now` panics, so this module uses
//! `web_time` for clocks and JS `setTimeout` for sleeps.

#[cfg(not(target_arch = "wasm32"))]
pub(crate) use native::*;
#[cfg(target_arch = "wasm32")]
pub(crate) use wasm::*;

#[cfg(not(target_arch = "wasm32"))]
mod native {
    pub use tokio::time::error::Elapsed;
    pub(crate) use tokio::time::{sleep, sleep_until, timeout, Instant};

    pub(crate) fn system_now() -> std::time::SystemTime {
        std::time::SystemTime::now()
    }
}

#[cfg(target_arch = "wasm32")]
mod wasm {
    use std::future::Future;
    use std::pin::Pin;
    use std::task::{Context, Poll};
    use std::time::Duration;

    use futures::channel::oneshot;
    use futures::future::{select, Either};
    pub(crate) use web_time::Instant;

    /// The error returned by [`timeout`] when the duration elapses first.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct Elapsed(());

    impl std::fmt::Display for Elapsed {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "deadline has elapsed")
        }
    }

    impl std::error::Error for Elapsed {}

    pub(crate) fn system_now() -> std::time::SystemTime {
        let since_epoch = web_time::SystemTime::now()
            .duration_since(web_time::UNIX_EPOCH)
            .unwrap_or_default();
        std::time::UNIX_EPOCH + since_epoch
    }

    /// A future that completes at a deadline.
    ///
    /// The JS timer lives in a local task and signals over a channel, because
    /// the timer handle is not `Send` and the server session future must be.
    #[derive(Debug)]
    pub(crate) struct Sleep {
        deadline: Instant,
        timer: Option<oneshot::Receiver<()>>,
    }

    pub(crate) fn sleep(duration: Duration) -> Sleep {
        sleep_until(Instant::now() + duration)
    }

    pub(crate) fn sleep_until(deadline: Instant) -> Sleep {
        Sleep {
            deadline,
            timer: None,
        }
    }

    impl Sleep {
        pub(crate) fn reset(self: Pin<&mut Self>, deadline: Instant) {
            let this = self.get_mut();
            // A timer that fires before a later deadline is re-armed in poll, so
            // only an earlier deadline needs a new timer. This keeps one JS timer
            // per Sleep when the keepalive is reset on every packet.
            if deadline < this.deadline {
                this.timer = None;
            }
            this.deadline = deadline;
        }
    }

    impl Future for Sleep {
        type Output = ();

        fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
            let this = self.get_mut();
            loop {
                let now = Instant::now();
                if now >= this.deadline {
                    this.timer = None;
                    return Poll::Ready(());
                }
                let remaining = this.deadline - now;
                let timer = this.timer.get_or_insert_with(|| arm(remaining));
                match Pin::new(timer).poll(cx) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(_) => this.timer = None,
                }
            }
        }
    }

    fn arm(duration: Duration) -> oneshot::Receiver<()> {
        let (mut tx, rx) = oneshot::channel();
        // Round up so the timer never fires before the deadline and poll does
        // not spin on zero-length timers.
        let millis = duration.as_nanos().div_ceil(1_000_000);
        let millis = u32::try_from(millis).unwrap_or(u32::MAX);
        wasm_bindgen_futures::spawn_local(async move {
            let timer = gloo_timers::future::TimeoutFuture::new(millis);
            let cancelled = tx.cancellation();
            futures::pin_mut!(timer, cancelled);
            // Dropping the timer clears the JS timeout when the Sleep is dropped.
            let fired = matches!(select(timer, cancelled).await, Either::Left(_));
            if fired {
                let _ = tx.send(());
            }
        });
        rx
    }

    pub(crate) async fn timeout<F: Future>(
        duration: Duration,
        future: F,
    ) -> Result<F::Output, Elapsed> {
        futures::pin_mut!(future);
        match select(future, sleep(duration)).await {
            Either::Left((output, _)) => Ok(output),
            Either::Right(_) => Err(Elapsed(())),
        }
    }
}
