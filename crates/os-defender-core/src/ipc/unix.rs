use std::io;
use std::path::Path;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{UnixListener as TokioUnixListener, UnixStream};
use tracing::info;

use super::transport::IpcStream;

pub struct RawStream(UnixStream);

impl RawStream {
    pub async fn connect(endpoint: &str) -> io::Result<Self> {
        let stream = UnixStream::connect(endpoint).await?;
        Ok(Self(stream))
    }
}

impl AsyncRead for RawStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().0).poll_read(cx, buf)
    }
}

impl AsyncWrite for RawStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().0).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().0).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().0).poll_shutdown(cx)
    }
}

pub struct IpcListener {
    inner: TokioUnixListener,
}

impl IpcListener {
    pub async fn bind_default() -> io::Result<Self> {
        let endpoint = super::default_ipc_endpoint();
        Self::bind(&endpoint).await
    }

    pub async fn bind(endpoint: &str) -> io::Result<Self> {
        let path = Path::new(endpoint);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let _ = std::fs::remove_file(path);
        let inner = TokioUnixListener::bind(path)?;
        info!(path = %path.display(), "IPC listening (unix socket)");
        Ok(Self { inner })
    }

    pub async fn accept(&self) -> io::Result<IpcStream> {
        let (stream, _addr) = self.inner.accept().await?;
        Ok(IpcStream::from_raw(RawStream(stream)))
    }
}
