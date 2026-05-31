//! Stateless AEAD seal/open plus a per-call key context (SPEC §5.2, ADR-0004).
//!
//! No I/O lives here. Given the call key — derived once via HKDF over the two
//! HELLO nonces — this module seals and opens frames with a per-direction 96-bit
//! counter and enforces a forward replay window. The same code runs identically
//! on both call sides; only the [`Direction`] tag differs.
//!
//! ## Key agreement (SPEC §5.2)
//! `key = HKDF-SHA256(PSK, salt = caller_nonce || callee_nonce,
//! info = "terminalphone/v2 call-key")`. The salt orders the nonces by *role*
//! (caller's nonce first), not by who is computing it, so both peers derive the
//! **identical** 32-byte AEAD key regardless of which side they are. Distinct
//! per-direction streams are achieved not with separate keys but with distinct
//! 4-byte [`Direction`] tags in the nonce, so a `(key, nonce)` pair is never
//! reused across the two directions.
//!
//! ## Nonce discipline (SPEC §5.2)
//! 96-bit AEAD nonce = `4-byte direction tag || 8-byte big-endian monotonic
//! per-direction counter`. Each side increments its own send counter via
//! [`CallKeys::next_seq`]; the counter is also the [`Seq`] bound into the AEAD
//! AAD. Because the counter is strictly monotonic per direction and the tag
//! differs per direction, the nonce is unique for the life of the key.
//!
//! ## Replay / integrity (SPEC §5.2)
//! The frame sequence is bound into the AAD and checked against a forward
//! [`ReplayWindow`]. Forged, modified, or replayed frames fail the tag (or the
//! window) and surface as [`Error::AuthFailed`]; callers drop them silently.

use std::sync::Mutex;

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::{Error, Result};

/// Negotiated AEAD cipher suite (SPEC §5.2). The id is exchanged in HELLO.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AeadSuite {
    /// AES-256-GCM — default; hardware-accelerated (AES-NI / ARMv8 crypto).
    Aes256Gcm,
    /// ChaCha20-Poly1305 — fallback for targets without AES hardware.
    ChaCha20Poly1305,
}

impl AeadSuite {
    /// Stable wire id carried in the HELLO frame.
    pub fn wire_id(self) -> u8 {
        match self {
            AeadSuite::Aes256Gcm => 0x01,
            AeadSuite::ChaCha20Poly1305 => 0x02,
        }
    }

    /// Parse a suite from its wire id; `None` for unknown suites.
    pub fn from_wire_id(id: u8) -> Option<Self> {
        match id {
            0x01 => Some(AeadSuite::Aes256Gcm),
            0x02 => Some(AeadSuite::ChaCha20Poly1305),
            _ => None,
        }
    }

    /// AEAD key length in bytes (32 for both supported suites).
    pub fn key_len(self) -> usize {
        32
    }
}

/// The pre-shared secret, exchanged out of band (SPEC §2). Zeroized on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Psk(pub [u8; 32]);

impl Psk {
    /// Construct from raw 32 bytes.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Psk(bytes)
    }

    /// Generate a fresh random PSK (used at first run when none exists).
    pub fn generate() -> Self {
        Psk(random_32())
    }
}

/// Each side's random 32-byte HELLO nonce; salts the per-call HKDF.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CallNonce(pub [u8; 32]);

impl CallNonce {
    /// Draw a fresh random call nonce.
    pub fn random() -> Self {
        CallNonce(random_32())
    }
}

/// Fill 32 bytes from the OS CSPRNG.
fn random_32() -> [u8; 32] {
    use rand::RngCore;
    let mut buf = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    buf
}

/// Direction tag forming the high 4 bytes of every 96-bit AEAD nonce (SPEC §5.2).
///
/// The caller and callee MUST agree on which role owns which tag so the two
/// directions never collide under the shared key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// Caller → callee traffic.
    CallerToCallee,
    /// Callee → caller traffic.
    CalleeToCaller,
}

impl Direction {
    /// The 4-byte direction tag prepended to the counter to form the nonce.
    pub fn tag(self) -> [u8; 4] {
        match self {
            Direction::CallerToCallee => [0x00, 0x00, 0x00, 0x01],
            Direction::CalleeToCaller => [0x00, 0x00, 0x00, 0x02],
        }
    }
}

/// Monotonic per-direction frame sequence number (8 bytes of the GCM nonce, and
/// bound into the AEAD AAD for replay protection).
pub type Seq = u64;

/// Sliding forward replay window over received [`Seq`] values (SPEC §5.2).
///
/// Accepts strictly-newer sequences and a bounded window of out-of-order ones;
/// rejects anything already seen or too old.
///
/// ## Bitmap encoding
/// `highest` is the greatest sequence accepted so far. Bit `i` of `bitmap`
/// (for `i` in `1..WIDTH`) records whether `highest - i` has been seen; the
/// `highest` position itself is tracked implicitly (it is always "seen" once
/// the window has advanced to it). A fresh, never-touched window has
/// `highest == 0` and `bitmap == 0`; the first call to
/// [`ReplayWindow::check_and_set`] establishes the baseline.
#[derive(Debug, Clone)]
pub struct ReplayWindow {
    /// Highest sequence accepted so far.
    highest: Seq,
    /// Bitmap of recently-seen sequences below `highest`.
    bitmap: u64,
    /// Whether any sequence has been accepted yet (distinguishes a genuine
    /// seq 0 from the zero-initialized empty state).
    seen_any: bool,
}

impl ReplayWindow {
    /// Window width in frames (size of the bitmap).
    pub const WIDTH: u64 = 64;

    /// A fresh window at the start of a call.
    pub fn new() -> Self {
        ReplayWindow {
            highest: 0,
            bitmap: 0,
            seen_any: false,
        }
    }

    /// Check-and-mark `seq`. Returns `true` if it is fresh (accept) and records it;
    /// `false` if it is a replay or too old (drop).
    pub fn check_and_set(&mut self, seq: Seq) -> bool {
        // First frame of the call: establish the baseline, mark `highest` seen.
        if !self.seen_any {
            self.seen_any = true;
            self.highest = seq;
            self.bitmap = 1; // bit 0 marks `highest` as seen
            return true;
        }

        if seq > self.highest {
            // Newer than anything seen: slide the window up by the gap.
            let shift = seq - self.highest;
            if shift >= Self::WIDTH {
                // Entire window scrolls past; nothing below stays in range.
                self.bitmap = 0;
            } else {
                self.bitmap <<= shift;
            }
            self.bitmap |= 1; // bit 0 marks the new `highest` as seen
            self.highest = seq;
            return true;
        }

        if seq == self.highest {
            // Exactly the current high-water mark: already seen.
            return false;
        }

        // seq < highest: within or below the trailing window.
        let offset = self.highest - seq;
        if offset >= Self::WIDTH {
            // Too old to be tracked → reject as a potential replay.
            return false;
        }
        let mask = 1u64 << offset;
        if self.bitmap & mask != 0 {
            // Already seen.
            return false;
        }
        self.bitmap |= mask;
        true
    }
}

impl Default for ReplayWindow {
    fn default() -> Self {
        Self::new()
    }
}

/// Per-call key context: holds the derived AEAD key and the two directional
/// counters. Created once per call via [`derive_call_keys`]; never re-derived
/// per message. Key material is zeroized on drop.
#[derive(ZeroizeOnDrop)]
pub struct CallKeys {
    /// 32-byte AEAD key from HKDF.
    key: [u8; 32],
    /// Negotiated suite (not secret).
    #[zeroize(skip)]
    suite: AeadSuite,
    /// Next sequence to use when sealing for each direction.
    #[zeroize(skip)]
    send_seq: Seq,
    /// Replay state for the receiving direction.
    ///
    /// Behind a `Mutex` because `open` takes `&self` (frozen signature) yet must
    /// mutate the window. The lock is uncontended on the hot path: a single
    /// receive task drives `open`. Zeroize-skipped: it holds no key material.
    #[zeroize(skip)]
    replay: Mutex<ReplayWindow>,
}

impl CallKeys {
    /// Seal `plaintext` for transmission in `dir` at sequence `seq`.
    ///
    /// `aad_bound` is the additional authenticated data the proto layer binds in
    /// (frame type + seq, per SPEC §5.2/§5.3); it is authenticated but not
    /// encrypted. Returns ciphertext with the AEAD tag appended.
    ///
    /// The full AAD is `aad_bound || dir.tag() || seq.to_be_bytes()`, so the
    /// direction and sequence are authenticated even if a caller passes an empty
    /// `aad_bound`. The nonce is `dir.tag() || seq` (12 bytes).
    pub fn seal(&self, dir: Direction, seq: Seq, aad_bound: &[u8], plaintext: &[u8]) -> Vec<u8> {
        let nonce = make_nonce(dir, seq);
        let aad = make_aad(aad_bound, dir, seq);
        // Encryption never fails for valid key/nonce sizes (which are fixed by
        // construction here), so a failure is a non-recoverable internal bug.
        aead_encrypt(self.suite, &self.key, &nonce, &aad, plaintext)
            .expect("AEAD seal with fixed-size key/nonce cannot fail")
    }

    /// Open a sealed frame received in `dir` at sequence `seq`.
    ///
    /// Returns the recovered plaintext, or [`Error::AuthFailed`] on a bad tag or
    /// replay-window rejection.
    ///
    /// Authentication happens *before* the window is advanced, so a frame with a
    /// forged sequence number cannot poison the replay state: only an
    /// authentic frame is recorded as seen.
    pub fn open(
        &self,
        dir: Direction,
        seq: Seq,
        aad_bound: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>> {
        let nonce = make_nonce(dir, seq);
        let aad = make_aad(aad_bound, dir, seq);

        // Authenticate + decrypt first. A bad tag → AuthFailed; the window is
        // untouched so attacker-chosen sequences cannot advance it.
        let plaintext = aead_decrypt(self.suite, &self.key, &nonce, &aad, ciphertext)
            .map_err(|_| Error::AuthFailed)?;

        // Frame is authentic. Now enforce replay: reject duplicates / too-old.
        let fresh = {
            let mut w = self
                .replay
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            w.check_and_set(seq)
        };
        if !fresh {
            return Err(Error::AuthFailed);
        }

        Ok(plaintext)
    }

    /// Allocate and return the next outbound sequence for the sending direction.
    pub fn next_seq(&mut self) -> Seq {
        let s = self.send_seq;
        self.send_seq = self.send_seq.wrapping_add(1);
        s
    }

    /// The negotiated suite for this call.
    pub fn suite(&self) -> AeadSuite {
        self.suite
    }
}

/// Build the 12-byte AEAD nonce: `4-byte direction tag || 8-byte BE counter`.
fn make_nonce(dir: Direction, seq: Seq) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[..4].copy_from_slice(&dir.tag());
    nonce[4..].copy_from_slice(&seq.to_be_bytes());
    nonce
}

/// Build the AAD bound into the tag: caller-supplied bytes, then the direction
/// tag and sequence so neither can be altered without failing authentication.
fn make_aad(aad_bound: &[u8], dir: Direction, seq: Seq) -> Vec<u8> {
    let mut aad = Vec::with_capacity(aad_bound.len() + 4 + 8);
    aad.extend_from_slice(aad_bound);
    aad.extend_from_slice(&dir.tag());
    aad.extend_from_slice(&seq.to_be_bytes());
    aad
}

/// Derive the per-call key context once from the PSK and both HELLO nonces.
///
/// `key = HKDF-SHA256(PSK, salt = caller_nonce || callee_nonce, info =
/// "terminalphone/v2 call-key")` (SPEC §5.2). `my_nonce`/`peer_nonce` are this
/// side's and the peer's nonces; the caller orders them into the canonical salt.
///
/// NOTE ON ORDERING: this function expects `my_nonce` to be the caller's nonce
/// and `peer_nonce` to be the callee's nonce — i.e. the salt is
/// `my_nonce || peer_nonce`. To get the *same* key on both sides, each peer must
/// pass the nonces in caller-then-callee order. The handshake code
/// (`proto::handshake_caller` / `handshake_callee`) is responsible for swapping
/// `my`/`peer` appropriately so the callee passes `(caller_nonce, callee_nonce)`
/// too. See the `both_sides_derive_identical_keys` test.
pub fn derive_call_keys(
    psk: &Psk,
    my_nonce: &CallNonce,
    peer_nonce: &CallNonce,
    suite: AeadSuite,
) -> CallKeys {
    use hkdf::Hkdf;
    use sha2::Sha256;

    let mut salt = [0u8; 64];
    salt[..32].copy_from_slice(&my_nonce.0);
    salt[32..].copy_from_slice(&peer_nonce.0);

    let hk = Hkdf::<Sha256>::new(Some(&salt), &psk.0);
    let mut key = [0u8; 32];
    hk.expand(CALL_KEY_INFO, &mut key)
        .expect("HKDF expand of 32 bytes is within the SHA-256 output limit");

    salt.zeroize();

    CallKeys {
        key,
        suite,
        send_seq: 0,
        replay: Mutex::new(ReplayWindow::new()),
    }
}

/// HKDF `info` string binding keys to this protocol version (SPEC §5.2).
pub const CALL_KEY_INFO: &[u8] = b"terminalphone/v2 call-key";

/// AEAD encryption dispatched on the negotiated suite. Returns the ciphertext
/// with the authentication tag appended.
fn aead_encrypt(
    suite: AeadSuite,
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    plaintext: &[u8],
) -> std::result::Result<Vec<u8>, ()> {
    use aead::{Aead, KeyInit, Payload};

    let payload = Payload {
        msg: plaintext,
        aad,
    };

    match suite {
        AeadSuite::Aes256Gcm => {
            use aes_gcm::{Aes256Gcm, Key, Nonce};
            let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
            cipher
                .encrypt(Nonce::from_slice(nonce), payload)
                .map_err(|_| ())
        }
        AeadSuite::ChaCha20Poly1305 => {
            use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
            let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
            cipher
                .encrypt(Nonce::from_slice(nonce), payload)
                .map_err(|_| ())
        }
    }
}

/// AEAD decryption dispatched on the negotiated suite. `Err(())` on a bad tag.
fn aead_decrypt(
    suite: AeadSuite,
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    ciphertext: &[u8],
) -> std::result::Result<Vec<u8>, ()> {
    use aead::{Aead, KeyInit, Payload};

    let payload = Payload {
        msg: ciphertext,
        aad,
    };

    match suite {
        AeadSuite::Aes256Gcm => {
            use aes_gcm::{Aes256Gcm, Key, Nonce};
            let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
            cipher
                .decrypt(Nonce::from_slice(nonce), payload)
                .map_err(|_| ())
        }
        AeadSuite::ChaCha20Poly1305 => {
            use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
            let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
            cipher
                .decrypt(Nonce::from_slice(nonce), payload)
                .map_err(|_| ())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PSK_BYTES: [u8; 32] = [0x42u8; 32];
    const CALLER_NONCE: CallNonce = CallNonce([0x11u8; 32]);
    const CALLEE_NONCE: CallNonce = CallNonce([0x22u8; 32]);

    fn psk() -> Psk {
        Psk::from_bytes(PSK_BYTES)
    }

    fn both_suites() -> [AeadSuite; 2] {
        [AeadSuite::Aes256Gcm, AeadSuite::ChaCha20Poly1305]
    }

    // ---- suite / nonce plumbing ------------------------------------------

    #[test]
    fn suite_wire_id_roundtrip() {
        for s in both_suites() {
            assert_eq!(AeadSuite::from_wire_id(s.wire_id()), Some(s));
            assert_eq!(s.key_len(), 32);
        }
        assert_eq!(AeadSuite::from_wire_id(0x00), None);
        assert_eq!(AeadSuite::from_wire_id(0xff), None);
    }

    #[test]
    fn nonce_layout_tag_then_be_counter() {
        let n = make_nonce(Direction::CallerToCallee, 0x0102030405060708);
        assert_eq!(&n[..4], &[0, 0, 0, 1]);
        assert_eq!(&n[4..], &0x0102030405060708u64.to_be_bytes());
        assert_eq!(n.len(), 12);

        let n2 = make_nonce(Direction::CalleeToCaller, 0);
        assert_eq!(&n2[..4], &[0, 0, 0, 2]);
        assert_eq!(&n2[4..], &[0u8; 8]);
    }

    #[test]
    fn direction_tags_distinct() {
        assert_ne!(
            Direction::CallerToCallee.tag(),
            Direction::CalleeToCaller.tag()
        );
    }

    // ---- round-trip -------------------------------------------------------

    #[test]
    fn seal_open_roundtrip_both_suites() {
        for suite in both_suites() {
            let send = derive_call_keys(&psk(), &CALLER_NONCE, &CALLEE_NONCE, suite);
            // Receiver derives the identical key independently.
            let recv = derive_call_keys(&psk(), &CALLER_NONCE, &CALLEE_NONCE, suite);

            let msg = b"hello terminalphone media frame";
            let aad = b"\x02"; // e.g. frame-type byte
            let ct = send.seal(Direction::CallerToCallee, 0, aad, msg);
            assert_ne!(&ct[..], &msg[..], "ciphertext must differ from plaintext");
            assert!(ct.len() > msg.len(), "ciphertext must carry an auth tag");

            let pt = recv
                .open(Direction::CallerToCallee, 0, aad, &ct)
                .expect("authentic frame should open");
            assert_eq!(&pt[..], &msg[..]);
        }
    }

    #[test]
    fn empty_plaintext_roundtrips() {
        let suite = AeadSuite::Aes256Gcm;
        let send = derive_call_keys(&psk(), &CALLER_NONCE, &CALLEE_NONCE, suite);
        let recv = derive_call_keys(&psk(), &CALLER_NONCE, &CALLEE_NONCE, suite);
        let ct = send.seal(Direction::CalleeToCaller, 0, b"", b"");
        assert_eq!(
            recv.open(Direction::CalleeToCaller, 0, b"", &ct).unwrap(),
            b""
        );
    }

    #[test]
    fn many_frames_in_order() {
        let suite = AeadSuite::ChaCha20Poly1305;
        let mut send = derive_call_keys(&psk(), &CALLER_NONCE, &CALLEE_NONCE, suite);
        let recv = derive_call_keys(&psk(), &CALLER_NONCE, &CALLEE_NONCE, suite);

        for _ in 0..3000u64 {
            let seq = send.next_seq();
            let payload = format!("frame {seq}").into_bytes();
            let ct = send.seal(Direction::CallerToCallee, seq, b"", &payload);
            let pt = recv.open(Direction::CallerToCallee, seq, b"", &ct).unwrap();
            assert_eq!(pt, payload);
        }
    }

    // ---- tamper rejection -------------------------------------------------

    #[test]
    fn tamper_body_rejected() {
        for suite in both_suites() {
            let send = derive_call_keys(&psk(), &CALLER_NONCE, &CALLEE_NONCE, suite);
            let recv = derive_call_keys(&psk(), &CALLER_NONCE, &CALLEE_NONCE, suite);
            let mut ct = send.seal(Direction::CallerToCallee, 0, b"", b"top secret payload");
            ct[0] ^= 0x01;
            assert!(matches!(
                recv.open(Direction::CallerToCallee, 0, b"", &ct),
                Err(Error::AuthFailed)
            ));
        }
    }

    #[test]
    fn tamper_tag_rejected() {
        let suite = AeadSuite::Aes256Gcm;
        let send = derive_call_keys(&psk(), &CALLER_NONCE, &CALLEE_NONCE, suite);
        let recv = derive_call_keys(&psk(), &CALLER_NONCE, &CALLEE_NONCE, suite);
        let mut ct = send.seal(Direction::CallerToCallee, 0, b"", b"top secret");
        let last = ct.len() - 1;
        ct[last] ^= 0x80;
        assert!(matches!(
            recv.open(Direction::CallerToCallee, 0, b"", &ct),
            Err(Error::AuthFailed)
        ));
    }

    #[test]
    fn wrong_aad_bound_rejected() {
        // Sealed under one frame-type AAD, opened under another → auth fails.
        let suite = AeadSuite::Aes256Gcm;
        let send = derive_call_keys(&psk(), &CALLER_NONCE, &CALLEE_NONCE, suite);
        let recv = derive_call_keys(&psk(), &CALLER_NONCE, &CALLEE_NONCE, suite);
        let ct = send.seal(Direction::CallerToCallee, 0, b"\x02", b"payload");
        assert!(
            recv.open(Direction::CallerToCallee, 0, b"\x03", &ct)
                .is_err()
        );
        // Correct AAD still works (fresh receiver to avoid replay state).
        let recv2 = derive_call_keys(&psk(), &CALLER_NONCE, &CALLEE_NONCE, suite);
        assert!(
            recv2
                .open(Direction::CallerToCallee, 0, b"\x02", &ct)
                .is_ok()
        );
    }

    #[test]
    fn wrong_seq_in_aad_rejected() {
        // The seq is bound into nonce + AAD: opening at a different seq fails.
        let suite = AeadSuite::ChaCha20Poly1305;
        let send = derive_call_keys(&psk(), &CALLER_NONCE, &CALLEE_NONCE, suite);
        let ct = send.seal(Direction::CallerToCallee, 5, b"", b"payload");

        let recv = derive_call_keys(&psk(), &CALLER_NONCE, &CALLEE_NONCE, suite);
        assert!(recv.open(Direction::CallerToCallee, 6, b"", &ct).is_err());
        // Correct seq authenticates.
        let recv2 = derive_call_keys(&psk(), &CALLER_NONCE, &CALLEE_NONCE, suite);
        assert!(recv2.open(Direction::CallerToCallee, 5, b"", &ct).is_ok());
    }

    #[test]
    fn wrong_direction_rejected() {
        // A frame sealed for one direction must not authenticate when opened
        // under the other (different tag → different nonce + AAD).
        let suite = AeadSuite::Aes256Gcm;
        let send = derive_call_keys(&psk(), &CALLER_NONCE, &CALLEE_NONCE, suite);
        let recv = derive_call_keys(&psk(), &CALLER_NONCE, &CALLEE_NONCE, suite);
        let ct = send.seal(Direction::CallerToCallee, 0, b"", b"payload");
        assert!(recv.open(Direction::CalleeToCaller, 0, b"", &ct).is_err());
    }

    #[test]
    fn cross_suite_open_fails() {
        let send = derive_call_keys(&psk(), &CALLER_NONCE, &CALLEE_NONCE, AeadSuite::Aes256Gcm);
        let recv = derive_call_keys(
            &psk(),
            &CALLER_NONCE,
            &CALLEE_NONCE,
            AeadSuite::ChaCha20Poly1305,
        );
        let ct = send.seal(Direction::CallerToCallee, 0, b"", b"payload");
        assert!(recv.open(Direction::CallerToCallee, 0, b"", &ct).is_err());
    }

    #[test]
    fn wrong_psk_open_fails() {
        let send = derive_call_keys(&psk(), &CALLER_NONCE, &CALLEE_NONCE, AeadSuite::Aes256Gcm);
        let other = Psk::from_bytes([0x99u8; 32]);
        let recv = derive_call_keys(&other, &CALLER_NONCE, &CALLEE_NONCE, AeadSuite::Aes256Gcm);
        let ct = send.seal(Direction::CallerToCallee, 0, b"", b"payload");
        assert!(recv.open(Direction::CallerToCallee, 0, b"", &ct).is_err());
    }

    // ---- replay rejection -------------------------------------------------

    #[test]
    fn replay_rejected() {
        let suite = AeadSuite::ChaCha20Poly1305;
        let send = derive_call_keys(&psk(), &CALLER_NONCE, &CALLEE_NONCE, suite);
        let recv = derive_call_keys(&psk(), &CALLER_NONCE, &CALLEE_NONCE, suite);

        let ct0 = send.seal(Direction::CallerToCallee, 0, b"", b"frame 0");
        let ct1 = send.seal(Direction::CallerToCallee, 1, b"", b"frame 1");

        assert!(recv.open(Direction::CallerToCallee, 0, b"", &ct0).is_ok());
        assert!(recv.open(Direction::CallerToCallee, 1, b"", &ct1).is_ok());
        // Replays are dropped.
        assert!(matches!(
            recv.open(Direction::CallerToCallee, 0, b"", &ct0),
            Err(Error::AuthFailed)
        ));
        assert!(matches!(
            recv.open(Direction::CallerToCallee, 1, b"", &ct1),
            Err(Error::AuthFailed)
        ));
    }

    #[test]
    fn out_of_order_within_window_accepted() {
        let suite = AeadSuite::Aes256Gcm;
        let send = derive_call_keys(&psk(), &CALLER_NONCE, &CALLEE_NONCE, suite);
        let recv = derive_call_keys(&psk(), &CALLER_NONCE, &CALLEE_NONCE, suite);

        let cts: Vec<_> = (0..5u64)
            .map(|s| {
                send.seal(
                    Direction::CallerToCallee,
                    s,
                    b"",
                    format!("f{s}").as_bytes(),
                )
            })
            .collect();

        // Deliver out of order: 4, 1, 3, 0, 2 — all fresh.
        for s in [4u64, 1, 3, 0, 2] {
            assert!(
                recv.open(Direction::CallerToCallee, s, b"", &cts[s as usize])
                    .is_ok(),
                "seq {s} should be accepted"
            );
        }
        // Any replay now fails.
        assert!(
            recv.open(Direction::CallerToCallee, 2, b"", &cts[2])
                .is_err()
        );
    }

    #[test]
    fn forged_seq_does_not_poison_window() {
        // An attacker presents a far-future seq with garbage ciphertext. It must
        // fail auth WITHOUT advancing the window, so a later legitimate frame at
        // the real next seq still opens.
        let suite = AeadSuite::Aes256Gcm;
        let send = derive_call_keys(&psk(), &CALLER_NONCE, &CALLEE_NONCE, suite);
        let recv = derive_call_keys(&psk(), &CALLER_NONCE, &CALLEE_NONCE, suite);

        let ct0 = send.seal(Direction::CallerToCallee, 0, b"", b"frame 0");
        assert!(recv.open(Direction::CallerToCallee, 0, b"", &ct0).is_ok());

        // Forged frame at seq 10_000: bogus bytes, will fail the tag.
        let forged = vec![0u8; 64];
        assert!(
            recv.open(Direction::CallerToCallee, 10_000, b"", &forged)
                .is_err()
        );

        // Legitimate next frame still opens (window was NOT advanced to 10_000).
        let ct1 = send.seal(Direction::CallerToCallee, 1, b"", b"frame 1");
        assert!(recv.open(Direction::CallerToCallee, 1, b"", &ct1).is_ok());
    }

    // ---- ReplayWindow unit behavior --------------------------------------

    #[test]
    fn replay_window_basic() {
        let mut w = ReplayWindow::new();
        assert!(w.check_and_set(0));
        assert!(!w.check_and_set(0)); // dup
        assert!(w.check_and_set(1));
        assert!(w.check_and_set(5));
        assert!(w.check_and_set(3)); // in-window backfill
        assert!(!w.check_and_set(3)); // dup
        assert!(w.check_and_set(4));
        assert!(!w.check_and_set(5)); // dup highest
    }

    #[test]
    fn replay_window_too_old_rejected() {
        let mut w = ReplayWindow::new();
        assert!(w.check_and_set(1000));
        // Just inside the window (offset 63) is accepted.
        assert!(w.check_and_set(1000 - (ReplayWindow::WIDTH - 1)));
        // Exactly at the edge (offset == WIDTH) is too old.
        assert!(!w.check_and_set(1000 - ReplayWindow::WIDTH));
        // Far below is too old.
        assert!(!w.check_and_set(0));
    }

    #[test]
    fn replay_window_large_jump_clears_bitmap() {
        let mut w = ReplayWindow::new();
        assert!(w.check_and_set(0));
        assert!(w.check_and_set(1));
        // Jump far beyond the window width.
        assert!(w.check_and_set(10_000));
        // Old low sequences are now far outside the window → rejected.
        assert!(!w.check_and_set(0));
        assert!(!w.check_and_set(1));
        // But the new highest is marked seen.
        assert!(!w.check_and_set(10_000));
        // And a neighbor of the new highest is fresh.
        assert!(w.check_and_set(9_999));
    }

    // ---- nonce uniqueness -------------------------------------------------

    #[test]
    fn nonce_unique_per_seq_and_direction() {
        use std::collections::HashSet;
        let mut seen = HashSet::new();
        for dir in [Direction::CallerToCallee, Direction::CalleeToCaller] {
            for seq in 0..2000u64 {
                let n = make_nonce(dir, seq);
                assert!(seen.insert(n), "nonce reuse at dir={dir:?} seq={seq}");
            }
        }
        // 2 directions * 2000 sequences, all distinct.
        assert_eq!(seen.len(), 4000);
    }

    #[test]
    fn next_seq_is_monotonic() {
        let mut keys = derive_call_keys(&psk(), &CALLER_NONCE, &CALLEE_NONCE, AeadSuite::Aes256Gcm);
        for expected in 0..100u64 {
            assert_eq!(keys.next_seq(), expected);
        }
    }

    // ---- key agreement ----------------------------------------------------

    #[test]
    fn both_sides_derive_identical_keys() {
        // Caller passes (caller_nonce, callee_nonce); callee passes the same
        // canonical order. Both must agree byte-for-byte, proven via real
        // cross-side seal/open in BOTH directions.
        let suite = AeadSuite::ChaCha20Poly1305;
        let caller = derive_call_keys(&psk(), &CALLER_NONCE, &CALLEE_NONCE, suite);
        let callee = derive_call_keys(&psk(), &CALLER_NONCE, &CALLEE_NONCE, suite);

        // Direct key comparison (test-internal access).
        assert_eq!(caller.key, callee.key);

        // Caller → callee.
        let a = caller.seal(Direction::CallerToCallee, 0, b"", b"caller speaks");
        assert_eq!(
            callee.open(Direction::CallerToCallee, 0, b"", &a).unwrap(),
            b"caller speaks"
        );
        // Callee → caller.
        let b = callee.seal(Direction::CalleeToCaller, 0, b"", b"callee speaks");
        assert_eq!(
            caller.open(Direction::CalleeToCaller, 0, b"", &b).unwrap(),
            b"callee speaks"
        );
    }

    #[test]
    fn swapped_nonce_order_diverges() {
        // If a peer mis-orders the salt (callee-then-caller), the derived key
        // differs, so a role/ordering mistake fails loudly rather than silently
        // agreeing on a wrong key.
        let suite = AeadSuite::Aes256Gcm;
        let correct = derive_call_keys(&psk(), &CALLER_NONCE, &CALLEE_NONCE, suite);
        let swapped = derive_call_keys(&psk(), &CALLEE_NONCE, &CALLER_NONCE, suite);
        assert_ne!(correct.key, swapped.key);

        let ct = correct.seal(Direction::CallerToCallee, 0, b"", b"x");
        assert!(
            swapped
                .open(Direction::CallerToCallee, 0, b"", &ct)
                .is_err()
        );
    }

    #[test]
    fn different_nonces_yield_different_keys() {
        let suite = AeadSuite::Aes256Gcm;
        let call1 = derive_call_keys(&psk(), &CALLER_NONCE, &CALLEE_NONCE, suite);
        let other_nonce = CallNonce([0x33u8; 32]);
        let call2 = derive_call_keys(&psk(), &CALLER_NONCE, &other_nonce, suite);
        assert_ne!(
            call1.key, call2.key,
            "different call nonces → different keys"
        );
    }

    // ---- PSK / nonce generation ------------------------------------------

    #[test]
    fn psk_generate_is_random() {
        let a = Psk::generate();
        let b = Psk::generate();
        assert_ne!(a.0, b.0);
        assert_ne!(a.0, [0u8; 32]);
    }

    #[test]
    fn call_nonce_random_is_random() {
        let a = CallNonce::random();
        let b = CallNonce::random();
        assert_ne!(a.0, b.0);
    }

    #[test]
    fn call_key_info_is_protocol_string() {
        assert_eq!(CALL_KEY_INFO, b"terminalphone/v2 call-key");
    }
}
