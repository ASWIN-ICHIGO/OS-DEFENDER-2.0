use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

#[cfg(unix)]
mod platform {
    pub use super::super::unix::{IpcListener, RawStream};
}

#[cfg(windows)]
mod platform {
    pub use super::super::windows::{IpcListener, RawStream};
}

pub struct IpcStream {
    inner: platform::RawStream,
}

impl IpcStream {
    pub async fn connect_default() -> io::Result<Self> {
        let endpoint = super::default_ipc_endpoint();
        Self::connect(&endpoint).await
    }

    pub async fn connect(endpoint: &str) -> io::Result<Self> {
        let inner = platform::RawStream::connect(endpoint).await?;
        Ok(Self { inner })
    }

    #[cfg(unix)]
    pub(crate) fn from_raw(raw: platform::RawStream) -> Self {
        Self { inner: raw }
    }

    #[cfg(windows)]
    pub(crate) fn from_raw(raw: platform::RawStream) -> Self {
        Self { inner: raw }
    }
}

impl AsyncRead for IpcStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for IpcStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

pub use platform::IpcListener;
