use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use tokio::sync::mpsc::Sender;

use super::WindowSizeRef;
use crate::ChannelMsg;

/// A handle to the [`super::Channel`]'s to be able to transmit messages
/// to it and update it's `window_size`.
#[derive(Debug)]
pub struct ChannelRef {
    pub(super) sender: Sender<ChannelMsg>,
    pub(super) window_size: WindowSizeRef,
    /// sallyport: set when the session closes the channel because its
    /// queue was full. The reader shares it.
    pub(super) reader_too_slow: Arc<AtomicBool>,
}

impl ChannelRef {
    pub fn new(sender: Sender<ChannelMsg>) -> Self {
        Self {
            sender,
            window_size: WindowSizeRef::new(0),
            reader_too_slow: Default::default(),
        }
    }

    pub(crate) fn window_size(&self) -> &WindowSizeRef {
        &self.window_size
    }

    pub(crate) fn reader_too_slow(&self) -> Arc<AtomicBool> {
        self.reader_too_slow.clone()
    }

    pub(crate) fn mark_reader_too_slow(&self) {
        self.reader_too_slow.store(true, Ordering::Release);
    }
}

impl std::ops::Deref for ChannelRef {
    type Target = Sender<ChannelMsg>;

    fn deref(&self) -> &Self::Target {
        &self.sender
    }
}
