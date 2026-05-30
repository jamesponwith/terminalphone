// TerminalPhone — arti onion-service spike (go/no-go gate for the Rust rewrite)
//
// Proves the riskiest dependency of the self-contained binary: hosting a Tor
// hidden service *in-process* via arti (no `tor` daemon, no torrc, no socat) and
// moving bytes both directions. This replaces, in the bash script:
//   - the generated torrc HiddenService block (terminalphone.sh:418)
//   - `socat TCP-LISTEN:7777`         (the inbound listener,  :1350)
//   - `socat SOCKS4A:...:7777`        (the outbound dialer,   :1440)
//
// Usage:
//   rs-spike serve              # host an onion service, print address, echo inbound bytes
//   rs-spike dial <addr.onion>  # connect to an onion service and test a round-trip
//
// DataStream implements the *futures* AsyncRead/AsyncWrite (not tokio's).

use anyhow::{Context, Result};
use arti_client::config::CfgPath;
use arti_client::{TorClient, TorClientConfig};
use futures::io::{AsyncReadExt, AsyncWriteExt};
use futures::stream::StreamExt;
use safelog::DisplayRedacted; // HsId only implements DisplayRedacted, not Display (arti safety feature)
use tor_cell::relaycell::msg::Connected;
use tor_hsservice::config::OnionServiceConfig;
use tor_hsservice::handle_rend_requests;
use tor_proto::client::stream::IncomingStreamRequest;

/// Application port carried inside the onion circuit (matches LISTEN_PORT=7777).
const PORT: u16 = 7777;

#[tokio::main]
async fn main() -> Result<()> {
    // rustls 0.23+ won't pick a crypto backend implicitly; install the ring provider once.
    let _ = rustls::crypto::ring::default_provider().install_default();

    let mode = std::env::args().nth(1).unwrap_or_default();

    // Each role gets its own state/cache dir so serve+dial can run side-by-side
    // on one machine without fighting over arti's on-disk locks.
    let data_dir = format!(".arti-{}", if mode.is_empty() { "x" } else { &mode });
    let mut cfg = TorClientConfig::builder();
    cfg.storage()
        .cache_dir(CfgPath::new_literal(format!("{data_dir}/cache")))
        .state_dir(CfgPath::new_literal(format!("{data_dir}/state")));
    let config = cfg.build()?;

    eprintln!("[*] bootstrapping arti TorClient (first run downloads a consensus, ~30-60s)...");
    let client = TorClient::create_bootstrapped(config)
        .await
        .context("arti bootstrap failed")?;
    eprintln!("[+] bootstrapped.");

    match mode.as_str() {
        "serve" => serve(&client).await,
        "dial" => {
            let addr = std::env::args()
                .nth(2)
                .context("usage: rs-spike dial <address.onion>")?;
            dial(&client, &addr).await
        }
        _ => {
            eprintln!("usage: rs-spike [serve | dial <address.onion>]");
            Ok(())
        }
    }
}

/// Host an onion service and echo whatever inbound peers send (the callee role).
async fn serve<R: tor_rtcompat::Runtime>(client: &TorClient<R>) -> Result<()> {
    let svc_config = OnionServiceConfig::builder()
        .nickname("tphone-spike".parse()?)
        .build()?;

    let (service, rend_requests) = client
        .launch_onion_service(svc_config)?
        .context("an onion service with that nickname is already running")?;

    match service.onion_address() {
        Some(addr) => {
            // This is the line that matters: a working .onion minted by our own process.
            // Explicitly unredact — arti redacts onion addresses by default to avoid leaking them to logs.
            let shown = addr.display_unredacted();
            println!("ONION: {shown}");
            eprintln!("[+] hosting. publishing descriptor to the HSDirs (can take ~30-90s)...");
            eprintln!("    in another terminal: rs-spike dial {shown}");
        }
        None => eprintln!("[!] no onion address yet"),
    }

    // handle_rend_requests turns the rendezvous stream into per-app-stream requests.
    let mut streams = handle_rend_requests(rend_requests);
    while let Some(stream_request) = streams.next().await {
        match stream_request.request() {
            IncomingStreamRequest::Begin(begin) if begin.port() == PORT => {
                let onion_stream = stream_request.accept(Connected::new_empty()).await?;
                tokio::spawn(echo(onion_stream));
            }
            _ => {
                // Reject anything not destined for our app port.
                stream_request.shutdown_circuit().ok();
            }
        }
    }
    Ok(())
}

/// Echo loop for one accepted inbound stream.
async fn echo<S>(mut stream: S)
where
    S: AsyncReadExt + AsyncWriteExt + Unpin,
{
    let mut buf = [0u8; 4096];
    loop {
        match stream.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                eprintln!("[recv] {n} bytes inbound, echoing back");
                if stream.write_all(&buf[..n]).await.is_err() {
                    break;
                }
                let _ = stream.flush().await;
            }
        }
    }
    eprintln!("[*] inbound stream closed");
}

/// Dial a remote onion service and test a round-trip (the caller role).
async fn dial<R: tor_rtcompat::Runtime>(client: &TorClient<R>, addr: &str) -> Result<()> {
    let host = addr.trim().trim_end_matches('/');
    eprintln!("[*] connecting to {host}:{PORT} over Tor...");
    let mut stream = client
        .connect((host, PORT))
        .await
        .with_context(|| format!("failed to connect to {host}"))?;
    eprintln!("[+] circuit up. sending probe.");

    let probe = b"terminalphone-arti-roundtrip\n";
    stream.write_all(probe).await?;
    stream.flush().await?;

    let mut buf = [0u8; 4096];
    let n = stream.read(&mut buf).await?;
    let got = String::from_utf8_lossy(&buf[..n]);
    eprintln!("[+] echoed back {n} bytes: {got:?}");
    if buf[..n] == probe[..] {
        println!("ROUNDTRIP: OK");
    } else {
        println!("ROUNDTRIP: MISMATCH");
    }
    Ok(())
}
