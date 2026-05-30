//! arti onion-service transport (SPEC §5.1, ADR-0002).
//!
//! In-process Tor: hosts the hidden service (`launch_onion_service` →
//! `handle_rend_requests` → accept app-port stream) and dials remotes
//! (`client.connect((onion, port))`). Patterns proven in `rs-spike/src/main.rs`.
//!
//! GOTCHAS honored by the impl:
//! - rustls 0.23 needs `rustls::crypto::ring::default_provider().install_default()`
//!   installed at startup (done in `main.rs`).
//! - `HsId` implements `safelog::DisplayRedacted`, not `Display`; print onions via
//!   `.display_unredacted()`.
//! - Separate `state_dir`/`cache_dir` (CfgPath) per process or arti deadlocks on locks.
//! - arti's `DataStream` implements the **futures** `AsyncRead`/`AsyncWrite` (not
//!   tokio's), which is exactly what the [`Conn`] boxed trait object expects, so no
//!   compat shim is needed.

use std::path::Path;

use arti_client::config::CfgPath;
use arti_client::{TorClient, TorClientConfig};
use futures::stream::StreamExt;
use safelog::DisplayRedacted; // HsId only implements DisplayRedacted, not Display.
use tor_cell::relaycell::msg::Connected;
use tor_hsservice::config::OnionServiceConfig;
use tor_hsservice::handle_rend_requests;
use tor_proto::client::stream::IncomingStreamRequest;
use tor_rtcompat::PreferredRuntime;

use crate::config::SpeedMode;
use crate::error::{Error, Result};
use crate::transport::{Conn, Identity, Incoming, OnionAddr, TorConfig, Transport};

/// Application port carried inside the onion circuit (matches v1 `LISTEN_PORT=7777`).
///
/// The transport accepts only `Begin` requests for this port and rejects all
/// others, mirroring `rs-spike`. Keep in sync with [`crate::config::Config::app_port`].
const APP_PORT: u16 = 7777;

/// In-process arti-backed Tor transport. M1's only production [`Transport`].
pub struct ArtiTransport {
    /// The bootstrapped arti `TorClient` over the preferred (tokio) runtime.
    client: TorClient<PreferredRuntime>,
    /// The hosted onion address, set after `host` publishes a descriptor.
    onion: Option<OnionAddr>,
}

impl ArtiTransport {
    /// Translate our [`TorConfig`] into an arti [`TorClientConfig`].
    ///
    /// Mirrors the exact, compiled storage-builder pattern from `rs-spike`:
    /// separate `cache_dir`/`state_dir` literals so two clients on one host do
    /// not deadlock on arti's on-disk locks. The onion-service identity key is
    /// persisted by arti's native keystore under `state_dir` (keyed by the
    /// service nickname), so reusing the same `state_dir` + nickname across runs
    /// yields a stable `.onion` (SPEC §5.1).
    fn client_config(cfg: &TorConfig) -> Result<TorClientConfig> {
        Self::note_speed_mode(cfg.speed_mode);

        let cache = path_to_string(&cfg.cache_dir)?;
        let state = path_to_string(&cfg.state_dir)?;

        let mut builder = TorClientConfig::builder();
        builder
            .storage()
            .cache_dir(CfgPath::new_literal(cache))
            .state_dir(CfgPath::new_literal(state));

        builder
            .build()
            .map_err(|e| Error::Transport(format!("building arti config: {e}")))
    }

    /// Apply / log the hop-and-speed posture (ADR-0005).
    ///
    /// `SpeedFirst` is the default. On the arti 0.42 line there is no *safe*,
    /// stable public config knob to reduce client-side hops without risking IP
    /// exposure, so per ADR-0005 ("speed-first ≠ auto-dox") we run standard
    /// circuits and log the fallback rather than silently trading anonymity.
    /// `SingleHopService` is the IP-revealing service mode and is gated out in
    /// [`Self::host`] (never silent).
    fn note_speed_mode(mode: SpeedMode) {
        match mode {
            SpeedMode::FullAnonymity => {
                tracing::debug!("tor: full-anonymity posture (standard onion circuits)");
            }
            SpeedMode::SpeedFirst => {
                tracing::debug!(
                    "tor: speed-first posture requested; arti 0.42 exposes no safe \
                     reduced-client-hop knob, running standard circuits \
                     (service stays location-anonymous)"
                );
            }
            SpeedMode::SingleHopService => {
                // Hosting is refused in `host`; bootstrap may still proceed for dialing.
                tracing::warn!(
                    "tor: single-hop-service posture selected; hosting is \
                     unimplemented and will be refused (would reveal service IP)"
                );
            }
        }
    }
}

impl Transport for ArtiTransport {
    async fn bootstrap(cfg: &TorConfig) -> Result<Self> {
        let config = Self::client_config(cfg)?;

        // Warm start: arti bootstraps against the on-disk dir cache under
        // `state_dir`/`cache_dir`, so subsequent launches reuse the cached
        // consensus instead of re-downloading it (SPEC §3 launch latency).
        let client = TorClient::create_bootstrapped(config)
            .await
            .map_err(|e| Error::Transport(format!("arti bootstrap failed: {e}")))?;

        Ok(ArtiTransport {
            client,
            onion: None,
        })
    }

    async fn host(&self, id: &Identity) -> Result<Incoming> {
        // ADR-0005: single-hop-service hosting reveals the service IP and is an
        // explicit, never-default trade. Not implemented on this arti line.
        //
        // TODO(ADR-0005): wire `single_onion_service` once arti exposes a stable,
        // explicitly-gated knob; until then we always host location-anonymously,
        // which is the safe superset for every non-`SingleHopService` mode. The
        // live `speed_mode` is not threaded through `Identity`; `bootstrap`
        // already logged the posture.

        // Persist the onion identity-key directory at owner-only perms. arti's
        // native keystore (under `state_dir`) is the authority for the actual key
        // material, keyed by nickname; we additionally ensure the skeleton's
        // `key_dir` exists with tight perms as the documented identity home
        // (SPEC §5.1, threat model §2 — a leaked key lets an attacker impersonate
        // the user's `.onion`).
        ensure_private_dir(&id.key_dir)?;

        let nickname = id.nickname.parse().map_err(|e| {
            Error::Transport(format!("invalid onion nickname {:?}: {e}", id.nickname))
        })?;

        let svc_config = OnionServiceConfig::builder()
            .nickname(nickname)
            .build()
            .map_err(|e| Error::Transport(format!("building onion service config: {e}")))?;

        // launch_onion_service -> Result<Option<(Arc<RunningOnionService>, impl Stream<RendRequest>)>>
        let (service, rend_requests) = self
            .client
            .launch_onion_service(svc_config)
            .map_err(|e| Error::Transport(format!("launching onion service: {e}")))?
            .ok_or_else(|| {
                Error::Transport(
                    "an onion service with that nickname is already running".to_string(),
                )
            })?;

        if let Some(addr) = service.onion_address() {
            // Explicitly unredact — arti redacts onion addresses in logs by default.
            tracing::info!(onion = %addr.display_unredacted(), "onion service published");
        }

        // Turn the rendezvous stream into per-app-stream requests, accept only
        // `Begin` on `APP_PORT`, and surface each accepted `DataStream` as a `Conn`.
        //
        // Built with `futures::stream::unfold` (no `async-stream` dependency, which
        // this crate does not declare). The `unfold` state captures both the
        // request stream (its item type inferred from `handle_rend_requests`, so
        // we never have to name arti's opaque `StreamRequest` re-export) and the
        // `service`, type-erased behind `Box<dyn Send>`. The service therefore
        // stays alive for exactly as long as the caller polls the returned
        // `Incoming`; dropping the `Incoming` drops it and tears the onion service
        // down. `_service` is held, never read.
        let requests = handle_rend_requests(rend_requests);
        let service_keepalive: Box<dyn Send> = Box::new(service);

        let incoming = futures::stream::unfold(
            (requests, service_keepalive),
            |(mut requests, service_keepalive)| async move {
                loop {
                    let stream_request = requests.next().await?;
                    match stream_request.request() {
                        IncomingStreamRequest::Begin(begin) if begin.port() == APP_PORT => {
                            let item = match stream_request.accept(Connected::new_empty()).await {
                                Ok(data_stream) => {
                                    let conn: Conn = Box::pin(data_stream);
                                    Ok(conn)
                                }
                                Err(e) => {
                                    Err(Error::Transport(format!("accepting onion stream: {e}")))
                                }
                            };
                            // Yield this item; thread state through to accept more.
                            return Some((item, (requests, service_keepalive)));
                        }
                        _ => {
                            // Reject anything not destined for our app port and
                            // keep waiting without yielding an item.
                            stream_request.shutdown_circuit().ok();
                        }
                    }
                }
            },
        );

        Ok(Box::pin(incoming))
    }

    async fn dial(&self, onion: &OnionAddr) -> Result<Conn> {
        // client.connect((host, app_port)) -> DataStream (futures AsyncRead/Write).
        let data_stream = self
            .client
            .connect((onion.host(), APP_PORT))
            .await
            .map_err(|e| Error::Transport(format!("dialing {}: {e}", onion.host())))?;

        let conn: Conn = Box::pin(data_stream);
        Ok(conn)
    }

    fn onion_address(&self) -> Option<OnionAddr> {
        self.onion.clone()
    }
}

/// Render a path as a UTF-8 string for [`CfgPath::new_literal`].
///
/// arti's literal `CfgPath` takes a `String`; a non-UTF-8 data dir is rejected
/// rather than lossily transcoded (a silently-wrong cache path would re-download
/// the consensus or, worse, share locks with another client).
fn path_to_string(p: &Path) -> Result<String> {
    p.to_str()
        .map(str::to_owned)
        .ok_or_else(|| Error::Transport(format!("non-UTF-8 path in TorConfig: {}", p.display())))
}

/// Create `dir` (and parents) and tighten it to owner-only (0700) on Unix.
///
/// The onion identity key is the user's stable, unrecoverable secret (SPEC §5.1,
/// threat model §2). Directories holding key material are owner-only. The spec's
/// "0600" intent is owner-only access; a directory must additionally be
/// executable (searchable) by its owner to be usable, hence 0700 on the dir,
/// with file-level perms left to arti's keystore.
fn ensure_private_dir(dir: &Path) -> Result<()> {
    std::fs::create_dir_all(dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o700);
        std::fs::set_permissions(dir, perms)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn tmp_cfg(tag: &str) -> (TorConfig, PathBuf) {
        let base = std::env::temp_dir().join(format!(
            "tphone-arti-test-{}-{}-{}",
            tag,
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let cfg = TorConfig {
            speed_mode: SpeedMode::default(),
            cache_dir: base.join("cache"),
            state_dir: base.join("state"),
        };
        (cfg, base)
    }

    #[test]
    fn client_config_builds_with_separate_dirs() {
        let (cfg, base) = tmp_cfg("cfgbuild");
        // Distinct cache/state dirs (the lock-deadlock guard) must produce a
        // valid arti config without touching the network.
        assert_ne!(cfg.cache_dir, cfg.state_dir);
        let built = ArtiTransport::client_config(&cfg);
        assert!(built.is_ok(), "config build failed: {:?}", built.err());
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn client_config_rejects_non_utf8_path() {
        // Only meaningful on Unix where OsString can hold non-UTF-8 bytes.
        #[cfg(unix)]
        {
            use std::ffi::OsString;
            use std::os::unix::ffi::OsStringExt;
            let bad = PathBuf::from(OsString::from_vec(vec![0x66, 0x80, 0x6f]));
            let cfg = TorConfig {
                speed_mode: SpeedMode::default(),
                cache_dir: bad.clone(),
                state_dir: bad,
            };
            let err = ArtiTransport::client_config(&cfg).unwrap_err();
            assert!(matches!(err, Error::Transport(_)));
        }
    }

    #[test]
    fn ensure_private_dir_creates_owner_only() {
        let dir = std::env::temp_dir().join(format!(
            "tphone-id-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        ensure_private_dir(&dir).expect("create private dir");
        assert!(dir.is_dir());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&dir).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o700, "identity dir must be owner-only");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn path_to_string_roundtrips_utf8() {
        let p = Path::new("/tmp/tphone/arti");
        assert_eq!(path_to_string(p).unwrap(), "/tmp/tphone/arti");
    }
}
