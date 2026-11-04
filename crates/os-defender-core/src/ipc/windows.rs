use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::windows::named_pipe::{
    ClientOptions, NamedPipeClient, NamedPipeServer, ServerOptions,
};
use tracing::info;

use super::transport::IpcStream;

pub enum RawStream {
    Server(NamedPipeServer),
    Client(NamedPipeClient),
}

impl RawStream {
    pub async fn connect(endpoint: &str) -> io::Result<Self> {
        let client = ClientOptions::new().open(endpoint)?;
        Ok(RawStream::Client(client))
    }
}

impl AsyncRead for RawStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            RawStream::Server(s) => Pin::new(s).poll_read(cx, buf),
            RawStream::Client(c) => Pin::new(c).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for RawStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            RawStream::Server(s) => Pin::new(s).poll_write(cx, buf),
            RawStream::Client(c) => Pin::new(c).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            RawStream::Server(s) => Pin::new(s).poll_flush(cx),
            RawStream::Client(c) => Pin::new(c).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            RawStream::Server(s) => Pin::new(s).poll_shutdown(cx),
            RawStream::Client(c) => Pin::new(c).poll_shutdown(cx),
        }
    }
}

impl Unpin for RawStream {}

pub struct IpcListener {
    pipe_name: String,
    current: NamedPipeServer,
}

impl IpcListener {
    pub async fn bind_default() -> io::Result<Self> {
        let endpoint = super::default_ipc_endpoint();
        Self::bind(&endpoint).await
    }

    pub async fn bind(endpoint: &str) -> io::Result<Self> {
        let current = ServerOptions::new()
            .first_pipe_instance(true)
            .create(endpoint)?;
        info!(pipe = %endpoint, "IPC listening (named pipe)");
        Ok(Self {
            pipe_name: endpoint.to_string(),
            current,
        })
    }

    pub async fn accept(&mut self) -> io::Result<IpcStream> {
        self.current.connect().await?;
        let connected = std::mem::replace(
            &mut self.current,
            ServerOptions::new().create(&self.pipe_name)?,
        );
        Ok(IpcStream::from_raw(RawStream::Server(connected)))
    }
}
