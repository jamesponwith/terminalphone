//! Integration test covering the full integrated app via the headless
//! self-test path.
//!
//! Exercises the same logic the `selftest` subcommand runs: two in-process call
//! cores over the loopback transport, a real proto handshake, the synthetic
//! audio backend's capture→encode and decode→sink, AEAD seal/open, and an exact
//! PCM + message round-trip — proving the wired app works end to end without a
//! TTY, Tor, or an audio device.

#[tokio::test]
async fn selftest_round_trip_succeeds() {
    tphone::selftest::run()
        .await
        .expect("integrated self-test should round-trip tone + message exactly");
}
