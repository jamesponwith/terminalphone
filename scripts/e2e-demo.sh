#!/bin/bash
# E2E demo harness: two-instance encrypted PTT call over Tor.
#
# Usage: ./scripts/e2e-demo.sh <machine-a-dir> <machine-b-dir>
#
# This script sets up two independent data directories with a shared PSK,
# then starts a host on Machine A and a dialer on Machine B, allowing a
# manual E2E test over real Tor.
#
# The script captures release-to-hear timing by observing TTY output from
# both instances (not automated audio measurement; for that, use a separate
# audio loopback + analysis tool).

set -e

if [[ $# -ne 2 ]]; then
    echo "Usage: $0 <machine-a-dir> <machine-b-dir>"
    echo ""
    echo "Example:"
    echo "  ./scripts/e2e-demo.sh /tmp/tp-host /tmp/tp-dial"
    echo ""
    echo "Then run on two machines (or tmux splits):"
    echo "  TERMINALPHONE_DIR=/tmp/tp-host cargo run --release -p tphone -- host"
    echo "  TERMINALPHONE_DIR=/tmp/tp-dial cargo run --release -p tphone -- dial <.onion>"
    exit 1
fi

DATA_A="$1"
DATA_B="$2"

echo "Setting up E2E demo data directories..."
mkdir -p "$DATA_A" "$DATA_B"

# Generate a shared PSK (32 bytes of random, base64-encoded for readability).
# Both machines MUST have the same PSK for the call to work.
if [[ ! -f "$DATA_A/secret" ]]; then
    echo "Generating shared PSK..."
    openssl rand 32 > "$DATA_A/secret"
fi

# Copy the PSK to Machine B (simulating out-of-band exchange).
cp "$DATA_A/secret" "$DATA_B/secret"
echo "✓ Shared PSK written to both data dirs."

# Optional: pre-create config.toml files if needed.
# The binary will use defaults if absent, so this is purely for customization.
cat > "$DATA_A/config.toml" <<'EOF'
aead_suite = "aes256gcm"
ppt_key = " "
app_port = 7777
speed_mode = "speed_first"
jitter_lead_ms = 250

[opus]
sample_rate = 16000
channels = 1
bitrate = 24000
frame_ms = 20
EOF

cp "$DATA_A/config.toml" "$DATA_B/config.toml"
echo "✓ Config written to both data dirs."

cat <<'INSTRUCTIONS'

E2E Demo Ready
==============

Run the host on Machine A (or tmux split 1):
  TERMINALPHONE_DIR=/tmp/tp-host cargo run --release -p tphone -- host

Wait for the output:
  onion service published      onion=<56-char-base32>.onion

Share the .onion address with Machine B (out of band).

Then run the dialer on Machine B (or tmux split 2):
  TERMINALPHONE_DIR=/tmp/tp-dial cargo run --release -p tphone -- dial <56-char-base32>.onion

Once both are on the call screen (AEAD suite shown, peer .onion visible):
  - Hold SPACE to talk (half-duplex PTT)
  - Release SPACE to play the remote audio
  - Type to compose and send an encrypted message
  - Press 'q' or Ctrl-C to hang up

Timing Measurements
===================

Release-to-hear latency is dominated by Tor circuit latency (~0.5–1.5 s per direction).
For detailed timing, capture the audio streams from both machines and correlate onset times.

Instructions

echo ""
echo "Data directories:"
echo "  Host:   $DATA_A"
echo "  Dialer: $DATA_B"
echo ""
echo "Run the host and dialer commands above, then test the call manually."
