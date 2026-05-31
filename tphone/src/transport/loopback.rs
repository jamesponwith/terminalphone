//! In-process loopback transport for integration tests (ARCHITECTURE "Testing").
//!
//! No Tor: connects a hosted "service" to a dialer over an in-memory duplex pipe
//! so the full audio→proto→crypto→proto→audio path can be exercised without a
//! circuit. [`host`](Transport::host) and [`dial`](Transport::dial) rendezvous
//! in-process and hand back connected [`Conn`] endpoints.
//!
//! ## Why a hand-rolled pipe
//!
//! The [`Conn`] contract is **futures** `AsyncRead`/`AsyncWrite` (arti's
//! `DataStream` is futures-flavored, not tokio-flavored), and `tokio::io::duplex`
//! yields *tokio*-flavored streams. Rather than pull in `tokio_util::compat`,
//! this module implements a tiny channel-backed duplex ([`PipeEnd`]) directly on
//! the futures traits. Each direction is an `mpsc` of byte chunks; a writer is
//! flow-controlled by the bounded channel, and a reader sees EOF when the peer's
//! sender drops (mirroring a closed circuit).
//!
//! ## Rendezvous model
//!
//! A [`LoopbackTransport`] owns a single rendezvous slot. `host` parks an
//! [`Incoming`] stream that yields one freshly-paired endpoint for every `dial`
//! against the same transport instance; the dialer receives the opposite end.
//! Both endpoints are created together by [`pipe`], so a `dial` always meets a
//! ready host with no ordering constraint between the two calls.

use std::collections::VecDeque;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use futures::stream::Stream;
use futures::{AsyncRead, AsyncWrite};
use tokio::sync::mpsc;

use crate::error::{Error, Result};
use crate::transport::{Conn, Identity, Incoming, OnionAddr, TorConfig, Transport};

/// Channel depth for each direction of a loopback pipe.
///
/// Bounded so a runaway writer applies backpressure instead of buffering without
/// limit — matching the flow-control posture of a real `Conn`.
const PIPE_CAPACITY: usize = 64;

/// A fake [`Transport`] that pairs a host and a dialer over an in-memory pipe.
///
/// One instance backs one rendezvous: the [`Incoming`] returned by `host` and
/// every [`Conn`] returned by `dial` are wired to opposite ends of pipes created
/// on demand. Cloneable senders let an arbitrary number of dials pair against a
/// single hosted stream, which keeps multi-call integration tests simple.
pub struct LoopbackTransport {
    /// The synthetic onion address this loopback "hosts".
    onion: Option<OnionAddr>,
    /// Dialer→host channel of newly accepted host endpoints.
    ///
    /// `dial` pushes the host end here so the [`Incoming`] stream can yield it;
    /// it keeps the dialer end. `None` until `host` claims the receiver (a
    /// not-yet-hosting transport rejects dials, mirroring an unpublished onion).
    accept_tx: mpsc::UnboundedSender<Conn>,
    /// Receiver side, claimed once by the first [`host`](Transport::host) call.
    ///
    /// Behind a `Mutex<Option<_>>` so `host(&self, ..)` can `take()` it through a
    /// shared reference (the trait gives `&self`, not `&mut self`).
    accept_rx: std::sync::Mutex<Option<mpsc::UnboundedReceiver<Conn>>>,
}

impl LoopbackTransport {
    /// Create a loopback transport advertising the given synthetic onion address.
    ///
    /// The accept channel is allocated eagerly; the receiver is handed out by the
    /// first (and only) call to [`host`](Transport::host).
    pub fn new(onion: OnionAddr) -> Self {
        let (accept_tx, accept_rx) = mpsc::unbounded_channel();
        // Stash the receiver in a slot the first `host` call drains. We park it on
        // the struct via a thread-safe cell so the public surface stays the same.
        LoopbackTransport {
            onion: Some(onion),
            accept_tx,
            accept_rx: std::sync::Mutex::new(Some(accept_rx)),
        }
    }
}

impl LoopbackTransport {
    /// Build a bootstrap-style transport with no advertised address.
    fn unaddressed() -> Self {
        let (accept_tx, accept_rx) = mpsc::unbounded_channel();
        LoopbackTransport {
            onion: None,
            accept_tx,
            accept_rx: std::sync::Mutex::new(Some(accept_rx)),
        }
    }
}

impl Transport for LoopbackTransport {
    async fn bootstrap(_cfg: &TorConfig) -> Result<Self> {
        Ok(LoopbackTransport::unaddressed())
    }

    async fn host(&self, _id: &Identity) -> Result<Incoming> {
        // Claim the accept-receiver. Hosting twice on one transport is a misuse,
        // not a wire condition, so it surfaces as a transport error.
        let rx = self
            .accept_rx
            .lock()
            .expect("loopback accept_rx mutex poisoned")
            .take()
            .ok_or_else(|| Error::Transport("loopback transport already hosting".to_string()))?;
        Ok(Box::pin(AcceptStream { rx }))
    }

    async fn dial(&self, _onion: &OnionAddr) -> Result<Conn> {
        let (dialer_end, host_end) = pipe();
        // Deliver the host end to the parked Incoming stream. If no one is hosting
        // (receiver dropped or never claimed), the dial fails like an unreachable
        // onion would.
        self.accept_tx
            .send(host_end)
            .map_err(|_| Error::Transport("loopback dial: no host accepting".to_string()))?;
        Ok(dialer_end)
    }

    fn onion_address(&self) -> Option<OnionAddr> {
        self.onion.clone()
    }
}

/// The [`Incoming`] stream backing a hosted loopback service.
///
/// Yields one `Ok(Conn)` per `dial` and ends (`None`) once every dialer-side
/// sender has dropped, mirroring an onion service whose last circuit closed.
struct AcceptStream {
    rx: mpsc::UnboundedReceiver<Conn>,
}

impl Stream for AcceptStream {
    type Item = Result<Conn>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match self.rx.poll_recv(cx) {
            Poll::Ready(Some(conn)) => Poll::Ready(Some(Ok(conn))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}

/// Create a connected pair of in-memory endpoints (futures `AsyncRead`/`Write`).
///
/// Returns `(a, b)`: bytes written to `a` surface on `b`'s reader and vice versa.
/// Either end seeing its peer's sender dropped reports clean EOF on read.
fn pipe() -> (Conn, Conn) {
    let (a_to_b_tx, a_to_b_rx) = mpsc::channel(PIPE_CAPACITY);
    let (b_to_a_tx, b_to_a_rx) = mpsc::channel(PIPE_CAPACITY);

    let a = PipeEnd {
        outbound: PollSender::new(a_to_b_tx),
        inbound: b_to_a_rx,
        leftover: VecDeque::new(),
    };
    let b = PipeEnd {
        outbound: PollSender::new(b_to_a_tx),
        inbound: a_to_b_rx,
        leftover: VecDeque::new(),
    };
    (Box::pin(a), Box::pin(b))
}

/// One half of an in-memory duplex pipe, implementing **futures** byte traits.
///
/// Writes are chunked into `Vec<u8>` and pushed through a bounded channel (so a
/// full channel yields `Poll::Pending` on write, i.e. real backpressure). Reads
/// drain a per-end `leftover` buffer first, then pull the next chunk.
struct PipeEnd {
    /// Sender to the peer's reader, wrapped for `poll_ready`/`try_send` polling.
    outbound: PollSender,
    /// Receiver of chunks written by the peer.
    inbound: mpsc::Receiver<Vec<u8>>,
    /// Bytes received but not yet handed to a `poll_read` caller.
    leftover: VecDeque<u8>,
}

impl AsyncRead for PipeEnd {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        // Refill leftover from the channel if we have nothing buffered.
        if self.leftover.is_empty() {
            match self.inbound.poll_recv(cx) {
                Poll::Ready(Some(chunk)) => self.leftover.extend(chunk),
                // Peer's sender dropped and the channel drained: clean EOF.
                Poll::Ready(None) => return Poll::Ready(Ok(0)),
                Poll::Pending => return Poll::Pending,
            }
        }

        // Copy as much as fits; any remainder stays in `leftover`.
        let n = self.leftover.len().min(buf.len());
        for slot in buf.iter_mut().take(n) {
            *slot = self.leftover.pop_front().expect("leftover length checked");
        }
        Poll::Ready(Ok(n))
    }
}

impl AsyncWrite for PipeEnd {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        match self.outbound.poll_ready(cx) {
            Poll::Ready(Ok(())) => {}
            // Peer's reader dropped: a broken pipe, like a torn-down circuit.
            Poll::Ready(Err(())) => {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "loopback peer closed",
                )));
            }
            Poll::Pending => return Poll::Pending,
        }
        match self.outbound.send_item(buf.to_vec()) {
            Ok(()) => Poll::Ready(Ok(buf.len())),
            Err(()) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "loopback peer closed",
            ))),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // Chunks are delivered synchronously on accept by the channel; nothing buffered.
        Poll::Ready(Ok(()))
    }

    fn poll_close(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // Drop the sender so the peer's reader observes EOF.
        self.outbound.close();
        Poll::Ready(Ok(()))
    }
}

/// Minimal pollable wrapper over a bounded `mpsc::Sender`.
///
/// `tokio::sync::mpsc::Sender::send` is async-only; this exposes a `poll_ready` +
/// `send_item` pair so [`AsyncWrite::poll_write`] can apply backpressure without
/// holding a future across `poll` calls. A reserved permit, when held, guarantees
/// the immediately-following `send_item` succeeds without blocking.
struct PollSender {
    /// `None` once closed via [`PipeEnd::poll_close`].
    sender: Option<mpsc::Sender<Vec<u8>>>,
    /// A capacity slot reserved by `poll_ready`, consumed by the next `send_item`.
    permit: Option<mpsc::OwnedPermit<Vec<u8>>>,
}

impl PollSender {
    fn new(sender: mpsc::Sender<Vec<u8>>) -> Self {
        PollSender {
            sender: Some(sender),
            permit: None,
        }
    }

    /// Reserve a send slot. `Ready(Ok)` means the next `send_item` will not block;
    /// `Ready(Err)` means the receiver is gone.
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<std::result::Result<(), ()>> {
        if self.permit.is_some() {
            return Poll::Ready(Ok(()));
        }
        let sender = match self.sender.clone() {
            Some(s) => s,
            None => return Poll::Ready(Err(())),
        };
        // Drive a reserve future to readiness, caching the permit on success.
        let mut fut = Box::pin(sender.reserve_owned());
        match fut.as_mut().poll(cx) {
            Poll::Ready(Ok(permit)) => {
                self.permit = Some(permit);
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(_)) => Poll::Ready(Err(())),
            Poll::Pending => Poll::Pending,
        }
    }

    /// Send using the permit reserved by the preceding `poll_ready`.
    fn send_item(&mut self, item: Vec<u8>) -> std::result::Result<(), ()> {
        match self.permit.take() {
            Some(permit) => {
                // `OwnedPermit::send` returns the Sender; keep it so we can reserve again.
                self.sender = Some(permit.send(item));
                Ok(())
            }
            None => Err(()),
        }
    }

    /// Drop the sender (and any held permit) so the peer reader sees EOF.
    fn close(&mut self) {
        self.permit = None;
        self.sender = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::{AsyncReadExt, AsyncWriteExt};
    use std::path::PathBuf;

    fn test_identity() -> Identity {
        Identity {
            key_dir: PathBuf::from("/tmp/loopback-test"),
            nickname: "loopback".to_string(),
        }
    }

    /// host + dial rendezvous, then the two endpoints exchange bytes both ways.
    #[tokio::test]
    async fn host_and_dial_exchange_bytes() {
        let transport = LoopbackTransport::new(OnionAddr("loopback.onion".to_string()));

        let mut incoming = transport.host(&test_identity()).await.unwrap();
        let mut dialer = transport
            .dial(&OnionAddr("loopback.onion".to_string()))
            .await
            .unwrap();

        // The host side accepts the freshly-paired endpoint.
        let mut host_conn = {
            use futures::StreamExt;
            incoming.next().await.unwrap().unwrap()
        };

        // dialer -> host
        dialer.write_all(b"ping from dialer").await.unwrap();
        dialer.flush().await.unwrap();
        let mut buf = [0u8; 16];
        host_conn.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping from dialer");

        // host -> dialer
        host_conn.write_all(b"pong from hostxx").await.unwrap();
        host_conn.flush().await.unwrap();
        let mut buf2 = [0u8; 16];
        dialer.read_exact(&mut buf2).await.unwrap();
        assert_eq!(&buf2, b"pong from hostxx");
    }

    /// A large, chunked payload reassembles intact across the bounded channel,
    /// exercising the `leftover` buffer and write backpressure.
    #[tokio::test]
    async fn large_payload_roundtrips() {
        let transport = LoopbackTransport::new(OnionAddr("big.onion".to_string()));
        let mut incoming = transport.host(&test_identity()).await.unwrap();
        let mut dialer = transport
            .dial(&OnionAddr("big.onion".to_string()))
            .await
            .unwrap();
        let mut host_conn = {
            use futures::StreamExt;
            incoming.next().await.unwrap().unwrap()
        };

        let payload: Vec<u8> = (0..50_000u32).map(|i| (i % 251) as u8).collect();
        let expected = payload.clone();

        // Concurrent write/read so the bounded channel can't deadlock the writer.
        let writer = tokio::spawn(async move {
            dialer.write_all(&payload).await.unwrap();
            dialer.flush().await.unwrap();
            dialer.close().await.unwrap();
        });

        let mut received = Vec::new();
        host_conn.read_to_end(&mut received).await.unwrap();
        writer.await.unwrap();

        assert_eq!(received, expected);
    }

    /// Closing one end surfaces as EOF on the peer's reader.
    #[tokio::test]
    async fn close_yields_eof() {
        let (mut a, mut b) = pipe();
        a.write_all(b"last").await.unwrap();
        a.close().await.unwrap();
        drop(a);

        let mut buf = Vec::new();
        b.read_to_end(&mut buf).await.unwrap();
        assert_eq!(buf, b"last");
    }

    /// Dialing a transport with no host accepting fails rather than hanging.
    #[tokio::test]
    async fn dial_without_host_fails() {
        let transport = LoopbackTransport::new(OnionAddr("nohost.onion".to_string()));
        // Claim then immediately drop the Incoming so the accept receiver is gone.
        let incoming = transport.host(&test_identity()).await.unwrap();
        drop(incoming);

        // `Conn` is not `Debug`, so avoid `unwrap_err()` (which would Debug-print
        // the Ok value); match the Result directly instead.
        match transport.dial(&OnionAddr("nohost.onion".to_string())).await {
            Err(Error::Transport(_)) => {}
            Err(other) => panic!("expected Transport error, got {other:?}"),
            Ok(_) => panic!("dial without host unexpectedly succeeded"),
        }
    }

    /// `onion_address` reflects construction; bootstrap has none.
    #[tokio::test]
    async fn onion_address_reported() {
        let t = LoopbackTransport::new(OnionAddr("addr.onion".to_string()));
        assert_eq!(t.onion_address(), Some(OnionAddr("addr.onion".to_string())));
        let boot = LoopbackTransport::unaddressed();
        assert_eq!(boot.onion_address(), None);
    }
}
