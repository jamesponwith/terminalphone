//! Wire protocol: the only module that touches the bytes on the onion stream
//! (SPEC §5.3, ARCHITECTURE "proto").
//!
//! Frame format (length-prefixed binary):
//! ```text
//! ┌────────┬────────┬──────────────┬───────────────┐
//! │ ver:u8 │ type:u8│ len:u32 (BE) │ payload[len]  │
//! └────────┴────────┴──────────────┴───────────────┘
//! ```
//! `HELLO` is the only unsealed frame (it bootstraps the key). Everything after
//! is AEAD-sealed; the handshake exchanges HELLOs, derives the per-call key via
//! `crypto`, and returns a [`crate::crypto::CallKeys`] plus peer info.
//!
//! Streams are arti `DataStream`s implementing **futures** `AsyncRead`/`AsyncWrite`.

use futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::crypto::{AeadSuite, CallKeys, CallNonce, Direction, Psk, Seq};
use crate::error::{Error, Result};
use crate::transport::OnionAddr;

/// Protocol version byte (first byte of every frame).
pub const PROTO_VERSION: u8 = 0x02;

/// Hard cap on a single frame payload to bound allocation against a hostile peer.
pub const MAX_FRAME_LEN: u32 = 1 << 20; // 1 MiB

/// Wire type byte for each frame (SPEC §5.3 table).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FrameType {
    /// 0x01 — unsealed handshake.
    Hello = 0x01,
    /// 0x02 — sealed Opus audio.
    Audio = 0x02,
    /// 0x03 — sealed UTF-8 text.
    Msg = 0x03,
    /// 0x04 — sealed PTT-start control.
    PttStart = 0x04,
    /// 0x05 — sealed PTT-stop control.
    PttStop = 0x05,
    /// 0x06 — sealed keepalive ping.
    Ping = 0x06,
    /// 0x07 — sealed keepalive pong.
    Pong = 0x07,
    /// 0x08 — sealed graceful hangup.
    Hangup = 0x08,
    /// 0x09 — sealed mid-call AEAD re-negotiation.
    Cipher = 0x09,
}

impl FrameType {
    /// Parse a type byte; `None` for unknown types.
    pub fn from_u8(b: u8) -> Option<Self> {
        Some(match b {
            0x01 => FrameType::Hello,
            0x02 => FrameType::Audio,
            0x03 => FrameType::Msg,
            0x04 => FrameType::PttStart,
            0x05 => FrameType::PttStop,
            0x06 => FrameType::Ping,
            0x07 => FrameType::Pong,
            0x08 => FrameType::Hangup,
            0x09 => FrameType::Cipher,
            _ => return None,
        })
    }
}

/// The HELLO payload (SPEC §5.3): the only unsealed frame, bootstraps the key.
#[derive(Debug, Clone)]
pub struct Hello {
    /// Sender's own onion address (identity).
    pub onion: OnionAddr,
    /// Advertised AEAD suite id (SPEC §5.2 negotiation).
    pub suite: AeadSuite,
    /// Opus parameters the sender will encode with (sample_rate, channels, bitrate, frame_ms).
    pub opus: crate::config::OpusParams,
    /// 32-byte random call nonce salting the per-call HKDF.
    pub nonce: CallNonce,
}

// HELLO payload layout (all multi-byte integers big-endian):
//
//   hello_ver : u8                  (== HELLO_PAYLOAD_VERSION)
//   suite_id  : u8                  (AeadSuite::wire_id)
//   sample_rate : u32
//   bitrate     : u32
//   channels    : u8
//   frame_ms    : u8
//   nonce     : [u8; 32]
//   onion_len : u16
//   onion     : [u8; onion_len]     (UTF-8)
//
// The HELLO body is itself self-describing so a future version can grow it
// without colliding with the outer frame `ver` byte (which versions the codec,
// not the HELLO schema).
const HELLO_PAYLOAD_VERSION: u8 = 0x01;

impl Hello {
    /// Serialize the HELLO payload to its on-wire byte form.
    pub fn encode(&self) -> Vec<u8> {
        let onion = self.onion.host().as_bytes();
        let onion_len = onion.len();
        // Fixed prefix is 1+1+4+4+1+1+32 = 44 bytes, plus 2-byte onion length.
        let mut buf = Vec::with_capacity(44 + 2 + onion_len);
        buf.push(HELLO_PAYLOAD_VERSION);
        buf.push(self.suite.wire_id());
        buf.extend_from_slice(&self.opus.sample_rate.to_be_bytes());
        buf.extend_from_slice(&self.opus.bitrate.to_be_bytes());
        buf.push(self.opus.channels);
        buf.push(self.opus.frame_ms);
        buf.extend_from_slice(&self.nonce.0);
        // onion_len is bounded: v3 onions are ~62 chars, far below u16::MAX.
        let len16 = u16::try_from(onion_len).unwrap_or(u16::MAX);
        buf.extend_from_slice(&len16.to_be_bytes());
        buf.extend_from_slice(&onion[..len16 as usize]);
        buf
    }

    /// Parse a HELLO payload from bytes.
    pub fn decode(payload: &[u8]) -> Result<Self> {
        let mut r = Reader::new(payload);
        let hello_ver = r.u8()?;
        if hello_ver != HELLO_PAYLOAD_VERSION {
            return Err(Error::Proto(format!(
                "unsupported HELLO payload version {hello_ver:#04x}"
            )));
        }
        let suite_id = r.u8()?;
        let suite = AeadSuite::from_wire_id(suite_id).ok_or_else(|| {
            Error::Proto(format!("unknown AEAD suite id {suite_id:#04x} in HELLO"))
        })?;
        let sample_rate = r.u32()?;
        let bitrate = r.u32()?;
        let channels = r.u8()?;
        let frame_ms = r.u8()?;
        let nonce = CallNonce(r.array::<32>()?);
        let onion_len = r.u16()? as usize;
        let onion_bytes = r.bytes(onion_len)?;
        let onion = std::str::from_utf8(onion_bytes)
            .map_err(|_| Error::Proto("HELLO onion address is not valid UTF-8".into()))?;

        Ok(Hello {
            onion: OnionAddr(onion.to_string()),
            suite,
            opus: crate::config::OpusParams {
                sample_rate,
                channels,
                bitrate,
                frame_ms,
            },
            nonce,
        })
    }
}

/// A decoded protocol frame. Sealed variants carry ciphertext; the handshake
/// frame is plaintext.
#[derive(Debug, Clone)]
pub enum Frame {
    /// Unsealed handshake.
    Hello(Hello),
    /// Sealed Opus audio with its per-direction sequence.
    Audio {
        /// Monotonic frame sequence (also bound into AAD).
        seq: Seq,
        /// AEAD-sealed Opus payload.
        sealed: Vec<u8>,
    },
    /// Sealed UTF-8 text message with its per-direction sequence.
    Msg {
        /// Monotonic frame sequence (also bound into AAD), drawn from the same
        /// per-direction counter as `Audio` so the two never collide in the
        /// receiver's replay window.
        seq: Seq,
        /// AEAD-sealed text bytes.
        sealed: Vec<u8>,
    },
    /// Sealed PTT-start control.
    PttStart {
        /// Sealed control payload.
        sealed: Vec<u8>,
    },
    /// Sealed PTT-stop control.
    PttStop {
        /// Sealed control payload.
        sealed: Vec<u8>,
    },
    /// Sealed keepalive ping.
    Ping {
        /// Sealed control payload.
        sealed: Vec<u8>,
    },
    /// Sealed keepalive pong.
    Pong {
        /// Sealed control payload.
        sealed: Vec<u8>,
    },
    /// Sealed graceful hangup.
    Hangup {
        /// Sealed control payload.
        sealed: Vec<u8>,
    },
    /// Sealed mid-call AEAD re-negotiation request.
    Cipher {
        /// Sealed payload carrying the new suite id.
        sealed: Vec<u8>,
    },
}

impl Frame {
    /// The wire type byte for this frame.
    pub fn frame_type(&self) -> FrameType {
        match self {
            Frame::Hello(_) => FrameType::Hello,
            Frame::Audio { .. } => FrameType::Audio,
            Frame::Msg { .. } => FrameType::Msg,
            Frame::PttStart { .. } => FrameType::PttStart,
            Frame::PttStop { .. } => FrameType::PttStop,
            Frame::Ping { .. } => FrameType::Ping,
            Frame::Pong { .. } => FrameType::Pong,
            Frame::Hangup { .. } => FrameType::Hangup,
            Frame::Cipher { .. } => FrameType::Cipher,
        }
    }

    /// Serialize the frame *payload* (the bytes that follow the `ver|type|len`
    /// header). For `Audio` and `Msg` the 8-byte big-endian sequence is prefixed
    /// ahead of the sealed ciphertext; all other sealed variants are the raw
    /// ciphertext; `Hello` is the encoded plaintext HELLO body.
    fn encode_payload(&self) -> Vec<u8> {
        match self {
            Frame::Hello(h) => h.encode(),
            Frame::Audio { seq, sealed } | Frame::Msg { seq, sealed } => {
                encode_seq_payload(*seq, sealed)
            }
            Frame::PttStart { sealed }
            | Frame::PttStop { sealed }
            | Frame::Ping { sealed }
            | Frame::Pong { sealed }
            | Frame::Hangup { sealed }
            | Frame::Cipher { sealed } => sealed.clone(),
        }
    }

    /// Reconstruct a frame from its type byte and payload bytes.
    fn decode_payload(ty: FrameType, payload: Vec<u8>) -> Result<Self> {
        Ok(match ty {
            FrameType::Hello => Frame::Hello(Hello::decode(&payload)?),
            FrameType::Audio => {
                let (seq, sealed) = decode_seq_payload(&payload, "AUDIO")?;
                Frame::Audio { seq, sealed }
            }
            FrameType::Msg => {
                let (seq, sealed) = decode_seq_payload(&payload, "MSG")?;
                Frame::Msg { seq, sealed }
            }
            FrameType::PttStart => Frame::PttStart { sealed: payload },
            FrameType::PttStop => Frame::PttStop { sealed: payload },
            FrameType::Ping => Frame::Ping { sealed: payload },
            FrameType::Pong => Frame::Pong { sealed: payload },
            FrameType::Hangup => Frame::Hangup { sealed: payload },
            FrameType::Cipher => Frame::Cipher { sealed: payload },
        })
    }
}

/// Encode a sealed payload that carries an 8-byte big-endian sequence prefix
/// (used by `Audio` and `Msg`, which share the per-direction replay sequence).
fn encode_seq_payload(seq: Seq, sealed: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(8 + sealed.len());
    buf.extend_from_slice(&seq.to_be_bytes());
    buf.extend_from_slice(sealed);
    buf
}

/// Split the 8-byte big-endian sequence prefix off a `Audio`/`Msg` payload.
/// `what` names the frame type for the truncation error message.
fn decode_seq_payload(payload: &[u8], what: &str) -> Result<(Seq, Vec<u8>)> {
    if payload.len() < 8 {
        return Err(Error::Proto(format!(
            "{what} frame too short to hold an 8-byte sequence"
        )));
    }
    let mut seq_bytes = [0u8; 8];
    seq_bytes.copy_from_slice(&payload[..8]);
    let seq = Seq::from_be_bytes(seq_bytes);
    Ok((seq, payload[8..].to_vec()))
}

/// Write one frame to `w` in the `ver|type|len|payload` format.
pub async fn write_frame<W>(w: &mut W, frame: &Frame) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    let payload = frame.encode_payload();
    let len = u32::try_from(payload.len())
        .map_err(|_| Error::Proto("frame payload exceeds u32 length".into()))?;
    if len > MAX_FRAME_LEN {
        return Err(Error::Proto(format!(
            "frame payload {len} exceeds MAX_FRAME_LEN {MAX_FRAME_LEN}"
        )));
    }

    // ver | type | len(BE u32), then payload, in as few writes as practical.
    let mut header = [0u8; 6];
    header[0] = PROTO_VERSION;
    header[1] = frame.frame_type() as u8;
    header[2..6].copy_from_slice(&len.to_be_bytes());

    w.write_all(&header).await?;
    w.write_all(&payload).await?;
    w.flush().await?;
    Ok(())
}

/// Read one frame from `r`, validating version, type, and length bound.
pub async fn read_frame<R>(r: &mut R) -> Result<Frame>
where
    R: AsyncRead + Unpin,
{
    let mut header = [0u8; 6];
    read_exact_or_closed(r, &mut header).await?;

    let ver = header[0];
    if ver != PROTO_VERSION {
        return Err(Error::Proto(format!(
            "unsupported protocol version {ver:#04x} (expected {PROTO_VERSION:#04x})"
        )));
    }

    let ty = FrameType::from_u8(header[1])
        .ok_or_else(|| Error::Proto(format!("unknown frame type {:#04x}", header[1])))?;

    let len = u32::from_be_bytes([header[2], header[3], header[4], header[5]]);
    if len > MAX_FRAME_LEN {
        return Err(Error::Proto(format!(
            "frame length {len} exceeds MAX_FRAME_LEN {MAX_FRAME_LEN}"
        )));
    }

    let mut payload = vec![0u8; len as usize];
    if len > 0 {
        // A short read here is a truncated frame, not a clean close.
        r.read_exact(&mut payload)
            .await
            .map_err(|e| Error::Proto(format!("truncated frame payload: {e}")))?;
    }

    Frame::decode_payload(ty, payload)
}

/// Read exactly `buf.len()` bytes, mapping a clean EOF *at the frame boundary*
/// (zero bytes read) to [`Error::Closed`] and a mid-header EOF to a protocol
/// error. This lets a read loop distinguish a graceful peer close from a torn
/// connection.
async fn read_exact_or_closed<R>(r: &mut R, buf: &mut [u8]) -> Result<()>
where
    R: AsyncRead + Unpin,
{
    let mut filled = 0usize;
    while filled < buf.len() {
        let n = r.read(&mut buf[filled..]).await?;
        if n == 0 {
            if filled == 0 {
                return Err(Error::Closed);
            }
            return Err(Error::Proto("connection closed mid-frame header".into()));
        }
        filled += n;
    }
    Ok(())
}

/// Identity + parameters learned about the peer during the handshake.
#[derive(Debug, Clone)]
pub struct PeerInfo {
    /// The peer's onion address (from their HELLO).
    pub onion: OnionAddr,
    /// The negotiated AEAD suite (must match ours, else cipher-mismatch abort).
    pub suite: AeadSuite,
    /// The peer's Opus parameters (drives our decoder).
    pub opus: crate::config::OpusParams,
}

/// Validate that the peer's advertised suite matches ours, then build the shared
/// [`PeerInfo`]. Returns [`Error::CipherMismatch`] on disagreement so the
/// failure is explicit (SPEC §5.2 — never silently downgrade).
fn negotiate(my_hello: &Hello, peer_hello: &Hello) -> Result<PeerInfo> {
    if my_hello.suite != peer_hello.suite {
        return Err(Error::CipherMismatch {
            local: my_hello.suite,
            peer: peer_hello.suite,
        });
    }
    Ok(PeerInfo {
        onion: peer_hello.onion.clone(),
        suite: peer_hello.suite,
        opus: peer_hello.opus,
    })
}

/// Caller-side handshake: send our HELLO, read the peer's, derive the call key.
///
/// On suite disagreement, returns [`crate::error::Error::CipherMismatch`].
/// Returns the per-call key context (with this side tagged
/// [`Direction::CallerToCallee`]) and the learned peer info.
pub async fn handshake_caller<S>(
    stream: &mut S,
    psk: &Psk,
    my_hello: Hello,
) -> Result<(CallKeys, PeerInfo)>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // Caller speaks first to minimize round trips, then awaits the peer HELLO.
    write_frame(stream, &Frame::Hello(my_hello.clone())).await?;
    let peer_hello = read_hello(stream).await?;

    let peer = negotiate(&my_hello, &peer_hello)?;
    let keys = crate::crypto::derive_call_keys(psk, &my_hello.nonce, &peer_hello.nonce, peer.suite);
    // Direction tag is intrinsic to seal/open call sites; the proto layer simply
    // reports which role this side plays via the keys it derived.
    let _ = Direction::CallerToCallee;
    Ok((keys, peer))
}

/// Callee-side handshake: read the peer's HELLO, send ours, derive the call key.
///
/// This side is tagged [`Direction::CalleeToCaller`].
pub async fn handshake_callee<S>(
    stream: &mut S,
    psk: &Psk,
    my_hello: Hello,
) -> Result<(CallKeys, PeerInfo)>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // Callee reads the caller's HELLO first, then replies with its own.
    let peer_hello = read_hello(stream).await?;
    write_frame(stream, &Frame::Hello(my_hello.clone())).await?;

    let peer = negotiate(&my_hello, &peer_hello)?;
    // `derive_call_keys` builds the salt as `first_nonce || second_nonce` and
    // both sides MUST present the canonical caller-then-callee order to derive
    // an identical key. On the callee, the *caller's* nonce is the peer's, so we
    // pass `(peer_hello.nonce, my_hello.nonce)` = `(caller_nonce, callee_nonce)`.
    let keys = crate::crypto::derive_call_keys(psk, &peer_hello.nonce, &my_hello.nonce, peer.suite);
    let _ = Direction::CalleeToCaller;
    Ok((keys, peer))
}

/// Read exactly one frame and require it to be a HELLO; anything else before the
/// key is established is a protocol violation.
async fn read_hello<S>(stream: &mut S) -> Result<Hello>
where
    S: AsyncRead + Unpin,
{
    match read_frame(stream).await? {
        Frame::Hello(h) => Ok(h),
        other => Err(Error::Proto(format!(
            "expected HELLO during handshake, got {:?}",
            other.frame_type()
        ))),
    }
}

/// Minimal big-endian cursor for parsing fixed-layout payloads with explicit
/// bounds checks (every short read becomes a [`Error::Proto`]).
struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Reader { buf, pos: 0 }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self
            .pos
            .checked_add(n)
            .ok_or_else(|| Error::Proto("HELLO length overflow".into()))?;
        if end > self.buf.len() {
            return Err(Error::Proto("HELLO payload truncated".into()));
        }
        let s = &self.buf[self.pos..end];
        self.pos = end;
        Ok(s)
    }

    fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16> {
        let s = self.take(2)?;
        Ok(u16::from_be_bytes([s[0], s[1]]))
    }

    fn u32(&mut self) -> Result<u32> {
        let s = self.take(4)?;
        Ok(u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        let s = self.take(N)?;
        let mut out = [0u8; N];
        out.copy_from_slice(s);
        Ok(out)
    }

    fn bytes(&mut self, n: usize) -> Result<&'a [u8]> {
        self.take(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::OpusParams;

    // ---- An in-memory full-duplex pair implementing *futures* AsyncRead/Write.
    //
    // Built only on `futures` (default features) so the codec/handshake can be
    // exercised without arti or tokio's io traits. Each endpoint reads from one
    // unbounded channel and writes to the other; bytes are framed as Vec<u8>
    // chunks and re-buffered on the read side so partial reads behave like a
    // real stream.
    use futures::Stream; // brings `poll_next` into scope for the duplex read impl
    use futures::channel::mpsc::{UnboundedReceiver, UnboundedSender, unbounded};
    use futures::task::{Context, Poll};
    use std::pin::Pin;

    struct DuplexEnd {
        tx: UnboundedSender<Vec<u8>>,
        rx: UnboundedReceiver<Vec<u8>>,
        read_buf: Vec<u8>,
        read_pos: usize,
    }

    fn duplex() -> (DuplexEnd, DuplexEnd) {
        let (a_tx, b_rx) = unbounded::<Vec<u8>>();
        let (b_tx, a_rx) = unbounded::<Vec<u8>>();
        (
            DuplexEnd {
                tx: a_tx,
                rx: a_rx,
                read_buf: Vec::new(),
                read_pos: 0,
            },
            DuplexEnd {
                tx: b_tx,
                rx: b_rx,
                read_buf: Vec::new(),
                read_pos: 0,
            },
        )
    }

    impl AsyncRead for DuplexEnd {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut [u8],
        ) -> Poll<std::io::Result<usize>> {
            loop {
                if self.read_pos < self.read_buf.len() {
                    let avail = &self.read_buf[self.read_pos..];
                    let n = avail.len().min(buf.len());
                    buf[..n].copy_from_slice(&avail[..n]);
                    self.read_pos += n;
                    return Poll::Ready(Ok(n));
                }
                // Buffer drained; pull the next chunk.
                self.read_buf.clear();
                self.read_pos = 0;
                match Pin::new(&mut self.rx).poll_next(cx) {
                    Poll::Ready(Some(chunk)) => {
                        if chunk.is_empty() {
                            continue;
                        }
                        self.read_buf = chunk;
                    }
                    // Sender dropped -> clean EOF.
                    Poll::Ready(None) => return Poll::Ready(Ok(0)),
                    Poll::Pending => return Poll::Pending,
                }
            }
        }
    }

    impl AsyncWrite for DuplexEnd {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            // Unbounded channel never applies backpressure in these tests.
            match self.tx.unbounded_send(buf.to_vec()) {
                Ok(()) => Poll::Ready(Ok(buf.len())),
                Err(_) => Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "duplex peer dropped",
                ))),
            }
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            self.tx.close_channel();
            Poll::Ready(Ok(()))
        }
    }

    fn sample_hello(onion: &str, suite: AeadSuite) -> Hello {
        Hello {
            onion: OnionAddr(onion.to_string()),
            suite,
            opus: OpusParams {
                sample_rate: 16_000,
                channels: 1,
                bitrate: 24_000,
                frame_ms: 20,
            },
            nonce: CallNonce([7u8; 32]),
        }
    }

    fn all_sample_frames() -> Vec<Frame> {
        let sealed = b"\x00\x01\x02\xaa\xbb sealed-ciphertext".to_vec();
        vec![
            Frame::Hello(sample_hello(
                "exampleexampleexampleexampleexampleexampleexampleexample23id.onion",
                AeadSuite::ChaCha20Poly1305,
            )),
            Frame::Audio {
                seq: 0xdead_beef_0000_0042,
                sealed: sealed.clone(),
            },
            Frame::Audio {
                seq: 0,
                sealed: Vec::new(),
            },
            Frame::Msg {
                seq: 0x0000_0000_0000_0007,
                sealed: sealed.clone(),
            },
            Frame::Msg {
                seq: 0,
                sealed: Vec::new(),
            },
            Frame::PttStart {
                sealed: sealed.clone(),
            },
            Frame::PttStop {
                sealed: sealed.clone(),
            },
            Frame::Ping {
                sealed: sealed.clone(),
            },
            Frame::Pong {
                sealed: sealed.clone(),
            },
            Frame::Hangup {
                sealed: sealed.clone(),
            },
            Frame::Cipher { sealed },
        ]
    }

    fn assert_frame_eq(a: &Frame, b: &Frame) {
        assert_eq!(a.frame_type(), b.frame_type());
        match (a, b) {
            (Frame::Hello(x), Frame::Hello(y)) => {
                assert_eq!(x.onion, y.onion);
                assert_eq!(x.suite, y.suite);
                assert_eq!(x.opus, y.opus);
                assert_eq!(x.nonce, y.nonce);
            }
            (
                Frame::Audio {
                    seq: sx,
                    sealed: cx,
                },
                Frame::Audio {
                    seq: sy,
                    sealed: cy,
                },
            )
            | (
                Frame::Msg {
                    seq: sx,
                    sealed: cx,
                },
                Frame::Msg {
                    seq: sy,
                    sealed: cy,
                },
            ) => {
                assert_eq!(sx, sy);
                assert_eq!(cx, cy);
            }
            (Frame::PttStart { sealed: x }, Frame::PttStart { sealed: y })
            | (Frame::PttStop { sealed: x }, Frame::PttStop { sealed: y })
            | (Frame::Ping { sealed: x }, Frame::Ping { sealed: y })
            | (Frame::Pong { sealed: x }, Frame::Pong { sealed: y })
            | (Frame::Hangup { sealed: x }, Frame::Hangup { sealed: y })
            | (Frame::Cipher { sealed: x }, Frame::Cipher { sealed: y }) => {
                assert_eq!(x, y);
            }
            _ => panic!("frame variant mismatch after round-trip"),
        }
    }

    #[test]
    fn hello_payload_round_trips() {
        let h = sample_hello(
            "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwxyzid.onion",
            AeadSuite::Aes256Gcm,
        );
        let decoded = Hello::decode(&h.encode()).expect("decode HELLO");
        assert_eq!(decoded.onion, h.onion);
        assert_eq!(decoded.suite, h.suite);
        assert_eq!(decoded.opus, h.opus);
        assert_eq!(decoded.nonce, h.nonce);
    }

    #[test]
    fn codec_round_trips_every_frame_type() {
        futures::executor::block_on(async {
            for frame in all_sample_frames() {
                let (mut a, mut b) = duplex();
                write_frame(&mut a, &frame).await.expect("write_frame");
                let got = read_frame(&mut b).await.expect("read_frame");
                assert_frame_eq(&frame, &got);
            }
        });
    }

    #[test]
    fn read_frame_rejects_bad_version() {
        futures::executor::block_on(async {
            let (mut a, mut b) = duplex();
            // ver=0xFF, type=Msg, len=0
            a.write_all(&[0xFF, 0x03, 0, 0, 0, 0]).await.unwrap();
            let err = read_frame(&mut b).await.unwrap_err();
            assert!(matches!(err, Error::Proto(_)), "got {err:?}");
        });
    }

    #[test]
    fn read_frame_rejects_unknown_type() {
        futures::executor::block_on(async {
            let (mut a, mut b) = duplex();
            a.write_all(&[PROTO_VERSION, 0x7F, 0, 0, 0, 0])
                .await
                .unwrap();
            let err = read_frame(&mut b).await.unwrap_err();
            assert!(matches!(err, Error::Proto(_)), "got {err:?}");
        });
    }

    #[test]
    fn read_frame_rejects_oversized_len() {
        futures::executor::block_on(async {
            let (mut a, mut b) = duplex();
            let big = (MAX_FRAME_LEN + 1).to_be_bytes();
            a.write_all(&[PROTO_VERSION, 0x03, big[0], big[1], big[2], big[3]])
                .await
                .unwrap();
            let err = read_frame(&mut b).await.unwrap_err();
            assert!(matches!(err, Error::Proto(_)), "got {err:?}");
        });
    }

    #[test]
    fn read_frame_clean_close_is_closed_error() {
        futures::executor::block_on(async {
            let (a, mut b) = duplex();
            drop(a); // sender gone before any byte -> clean EOF at boundary
            let err = read_frame(&mut b).await.unwrap_err();
            assert!(matches!(err, Error::Closed), "got {err:?}");
        });
    }

    #[test]
    fn handshake_yields_identical_call_keys() {
        futures::executor::block_on(async {
            let psk = Psk::from_bytes([0x42u8; 32]);

            let caller_hello = {
                let mut h = sample_hello(
                    "calleronion000000000000000000000000000000id.onion",
                    AeadSuite::Aes256Gcm,
                );
                h.nonce = CallNonce([0x11u8; 32]);
                h
            };
            let callee_hello = {
                let mut h = sample_hello(
                    "calleeonion000000000000000000000000000000id.onion",
                    AeadSuite::Aes256Gcm,
                );
                h.nonce = CallNonce([0x22u8; 32]);
                h
            };

            let (mut caller_stream, mut callee_stream) = duplex();

            let psk_c = psk.clone();
            let psk_s = psk.clone();
            let ch = caller_hello.clone();
            let sh = callee_hello.clone();

            let (caller_res, callee_res) = futures::future::join(
                handshake_caller(&mut caller_stream, &psk_c, ch),
                handshake_callee(&mut callee_stream, &psk_s, sh),
            )
            .await;

            let (caller_keys, caller_peer) = caller_res.expect("caller handshake");
            let (callee_keys, callee_peer) = callee_res.expect("callee handshake");

            // Each side learned the other's identity/params.
            assert_eq!(caller_peer.onion, callee_hello.onion);
            assert_eq!(callee_peer.onion, caller_hello.onion);
            assert_eq!(caller_peer.suite, AeadSuite::Aes256Gcm);
            assert_eq!(callee_peer.suite, AeadSuite::Aes256Gcm);

            // The two ends must hold the same key material. We can't read the
            // private key bytes, so prove equality through the AEAD: a frame
            // sealed by the caller (CallerToCallee) opens on the callee using
            // the same direction + seq + AAD.
            let aad = b"frame-type-and-seq";
            let pt = b"identical-call-keys-proof";
            let sealed = caller_keys.seal(Direction::CallerToCallee, 0, aad, pt);
            let opened = callee_keys
                .open(Direction::CallerToCallee, 0, aad, &sealed)
                .expect("callee opens caller-sealed frame -> keys match");
            assert_eq!(opened, pt);

            // And the reverse direction.
            let sealed_back = callee_keys.seal(Direction::CalleeToCaller, 0, aad, pt);
            let opened_back = caller_keys
                .open(Direction::CalleeToCaller, 0, aad, &sealed_back)
                .expect("caller opens callee-sealed frame -> keys match");
            assert_eq!(opened_back, pt);
        });
    }

    // ---- randomized robustness (CI-safe "fuzz"; see tphone/fuzz for libfuzzer) ----

    /// `read_frame` must never panic on arbitrary bytes — only ever return
    /// `Ok(frame)` or `Err(_)`. A hostile peer controls these bytes, so a panic
    /// would be a remote DoS. Seeded for reproducibility.
    #[test]
    fn read_frame_never_panics_on_random_bytes() {
        use rand::{Rng, RngCore, SeedableRng, rngs::StdRng};
        let mut rng = StdRng::seed_from_u64(0xF0_0D_C0_DE);
        futures::executor::block_on(async {
            for _ in 0..4000 {
                let len = rng.gen_range(0..2048usize);
                let mut bytes = vec![0u8; len];
                rng.fill_bytes(&mut bytes);
                let (mut a, mut b) = duplex();
                a.write_all(&bytes).await.ok();
                drop(a); // EOF so a short/truncated read terminates instead of hanging
                // Must resolve to a Result without panicking; either arm is fine.
                let _ = read_frame(&mut b).await;
            }
        });
    }

    /// Any decodable frame must survive an encode→write→read round-trip,
    /// including adversarial seq/payload values. Builds random sealed frames.
    #[test]
    fn random_frames_round_trip() {
        use rand::{Rng, RngCore, SeedableRng, rngs::StdRng};
        let mut rng = StdRng::seed_from_u64(0x5EED_1234);
        futures::executor::block_on(async {
            for _ in 0..1500 {
                let plen = rng.gen_range(0..512usize);
                let mut sealed = vec![0u8; plen];
                rng.fill_bytes(&mut sealed);
                let seq: u64 = rng.r#gen();

                let frame = match rng.gen_range(0..8u8) {
                    0 => Frame::Audio {
                        seq,
                        sealed: sealed.clone(),
                    },
                    1 => Frame::Msg {
                        seq,
                        sealed: sealed.clone(),
                    },
                    2 => Frame::PttStart {
                        sealed: sealed.clone(),
                    },
                    3 => Frame::PttStop {
                        sealed: sealed.clone(),
                    },
                    4 => Frame::Ping {
                        sealed: sealed.clone(),
                    },
                    5 => Frame::Pong {
                        sealed: sealed.clone(),
                    },
                    6 => Frame::Hangup {
                        sealed: sealed.clone(),
                    },
                    _ => Frame::Cipher {
                        sealed: sealed.clone(),
                    },
                };

                let (mut a, mut b) = duplex();
                write_frame(&mut a, &frame).await.expect("write_frame");
                let got = read_frame(&mut b).await.expect("read_frame");
                assert_frame_eq(&frame, &got);
            }
        });
    }

    #[test]
    fn handshake_suite_mismatch_errors() {
        futures::executor::block_on(async {
            let psk = Psk::from_bytes([0x42u8; 32]);

            let caller_hello = sample_hello("calleronion.onion", AeadSuite::Aes256Gcm);
            let callee_hello = sample_hello("calleeonion.onion", AeadSuite::ChaCha20Poly1305);

            let (mut caller_stream, mut callee_stream) = duplex();

            let psk_c = psk.clone();
            let psk_s = psk.clone();

            let (caller_res, callee_res) = futures::future::join(
                handshake_caller(&mut caller_stream, &psk_c, caller_hello),
                handshake_callee(&mut callee_stream, &psk_s, callee_hello),
            )
            .await;

            for res in [caller_res, callee_res] {
                match res {
                    Err(Error::CipherMismatch { .. }) => {}
                    Err(other) => panic!("expected CipherMismatch, got {other:?}"),
                    Ok(_) => panic!("expected CipherMismatch, got Ok"),
                }
            }
        });
    }
}
