//! libFuzzer target for the wire codec (tp-1u5).
//!
//! Feeds arbitrary attacker-controlled bytes to `proto::read_frame`, which must
//! only ever return `Ok`/`Err` — never panic, over-allocate past `MAX_FRAME_LEN`,
//! or hang. The CI-runnable counterpart lives in `proto::tests`
//! (`read_frame_never_panics_on_random_bytes`); this target explores far deeper.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // A `futures` in-memory reader yields EOF after `data`, so a truncated frame
    // terminates rather than blocking. No tokio/Tor needed.
    let mut cursor = futures::io::Cursor::new(data);
    let _ = futures::executor::block_on(tphone::proto::read_frame(&mut cursor));
});
