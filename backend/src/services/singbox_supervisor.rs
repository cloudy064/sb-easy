//! In-process sing-box supervisor.
//!
//! When `SINGBOX_MANAGED=true`, sb-easy owns the sing-box lifecycle itself: it
//! renders the `self` host's config, spawns `sing-box run -c <path>`, reloads it
//! on config change (SIGHUP), and respawns it if it crashes. The operator runs
//! and manages only sb-easy — there is no separate sing-box service.
//!
//! This supersedes the external-reload self-agent (which shells out to
//! systemctl). Disabled by default so existing deployments are unaffected.

use std::process::Stdio;
use std::time::Duration;

use tokio::process::{Child, Command};
use tracing::{error, info, warn};

use crate::services::self_agent::render_self;
use crate::AppState;

/// Default config path when SELF_SINGBOX_CONFIG_PATH is not set.
const DEFAULT_CONFIG_PATH: &str = "data/sing-box.gen.json";

pub async fn run(state: AppState) {
    if !state.cfg.singbox_managed {
        return;
    }
    let bin = state.cfg.singbox_bin.clone();
    let path = {
        let p = state.cfg.self_singbox_config_path.trim();
        if p.is_empty() { DEFAULT_CONFIG_PATH.to_string() } else { p.to_string() }
    };
    let interval = Duration::from_secs(state.cfg.self_singbox_interval);
    info!("sing-box supervisor enabled: bin={bin} config={path} (every {}s)", state.cfg.self_singbox_interval);

    let mut child: Option<Child> = None;
    let mut last_etag = String::new();

    loop {
        // 1. Desired config changed? Write it and reload (or start) sing-box.
        if let Some((etag, config_str)) = render_self(&state).await {
            if etag != last_etag {
                if let Err(e) = tokio::fs::write(&path, &config_str).await {
                    error!("sing-box config write to {path} failed: {e}");
                } else {
                    last_etag = etag;
                    let alive = child.as_mut().map(is_alive).unwrap_or(false);
                    if alive {
                        info!("config changed → reloading sing-box");
                        if let Some(c) = child.as_ref() {
                            reload(c);
                        }
                    } else {
                        child = spawn(&bin, &path);
                    }
                }
            }
        }

        // 2. Keep it alive: respawn if it exited unexpectedly.
        match child.as_mut() {
            Some(c) => {
                if let Ok(Some(status)) = c.try_wait() {
                    warn!("sing-box exited ({status}) — respawning");
                    child = spawn(&bin, &path);
                }
            }
            None if !last_etag.is_empty() => {
                // Config exists but no process (initial spawn failed) — retry.
                child = spawn(&bin, &path);
            }
            None => {}
        }

        tokio::time::sleep(interval).await;
    }
}

/// Spawn `sing-box run -c <path>`. Returns None if spawning fails.
fn spawn(bin: &str, config_path: &str) -> Option<Child> {
    match Command::new(bin)
        .args(["run", "-c", config_path])
        .stdin(Stdio::null())
        .kill_on_drop(false)
        .spawn()
    {
        Ok(c) => {
            info!("sing-box started (pid {:?})", c.id());
            Some(c)
        }
        Err(e) => {
            error!("failed to start sing-box ({bin}): {e}");
            None
        }
    }
}

fn is_alive(c: &mut Child) -> bool {
    matches!(c.try_wait(), Ok(None))
}

/// Ask sing-box to reload its config in place (SIGHUP). Falls back to nothing if
/// the pid is unavailable; the next loop tick will respawn if it died.
fn reload(c: &Child) {
    let Some(pid) = c.id() else { return };
    let _ = std::process::Command::new("kill")
        .args(["-HUP", &pid.to_string()])
        .status();
}
