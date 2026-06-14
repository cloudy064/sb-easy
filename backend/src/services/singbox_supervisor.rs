//! In-process sing-box supervisor.
//!
//! sb-easy can own the sing-box lifecycle itself: write the config, spawn
//! `sing-box run -c <path>`, reload it on config change (SIGHUP), and respawn it
//! if it crashes. The operator runs and manages only sb-easy — there is no
//! separate sing-box service.
//!
//! Used in two places: the panel's `self` host (when SINGBOX_MANAGED=true) and
//! agent mode (`sb-easy agent`), both via the reusable `Singbox` handle.

use std::process::Stdio;
use std::time::Duration;

use tokio::process::{Child, Command};
use tracing::{error, info, warn};

use crate::services::self_agent::render_self;
use crate::AppState;

/// Default config path when none is configured.
pub const DEFAULT_CONFIG_PATH: &str = "data/sing-box.gen.json";

/// A supervised sing-box process: write config, reload, respawn.
pub struct Singbox {
    bin: String,
    config_path: String,
    child: Option<Child>,
}

impl Singbox {
    pub fn new(bin: String, config_path: String) -> Self {
        Self { bin, config_path, child: None }
    }

    /// Write the config and load it: SIGHUP-reload a live child, else spawn one.
    pub async fn apply(&mut self, config_str: &str) -> std::io::Result<()> {
        tokio::fs::write(&self.config_path, config_str).await?;
        if self.is_alive() {
            info!("config changed → reloading sing-box");
            self.reload_now();
        } else {
            self.child = spawn(&self.bin, &self.config_path);
        }
        Ok(())
    }

    /// Respawn if the process exited unexpectedly. Call each tick.
    pub fn ensure_alive(&mut self) {
        if let Some(c) = self.child.as_mut() {
            if let Ok(Some(status)) = c.try_wait() {
                warn!("sing-box exited ({status}) — respawning");
                self.child = spawn(&self.bin, &self.config_path);
            }
        }
    }

    /// Start the process if it isn't running (config must already be written).
    pub fn start_if_stopped(&mut self) {
        if !self.is_alive() {
            self.child = spawn(&self.bin, &self.config_path);
        }
    }

    /// SIGHUP the child so it re-reads its config in place.
    pub fn reload_now(&self) {
        if let Some(pid) = self.child.as_ref().and_then(|c| c.id()) {
            let _ = std::process::Command::new("kill")
                .args(["-HUP", &pid.to_string()])
                .status();
        }
    }

    /// Hard restart: kill then respawn.
    pub async fn restart(&mut self) {
        if let Some(mut c) = self.child.take() {
            let _ = c.kill().await;
        }
        self.child = spawn(&self.bin, &self.config_path);
    }

    pub fn is_alive(&mut self) -> bool {
        matches!(self.child.as_mut().map(|c| c.try_wait()), Some(Ok(None)))
    }
}

/// Spawn `sing-box run -c <path>`. Returns None if spawning fails.
fn spawn(bin: &str, config_path: &str) -> Option<Child> {
    match Command::new(bin)
        .args(["run", "-c", config_path])
        .stdin(Stdio::null())
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

/// Panel-side supervisor loop for the built-in `self` host (SINGBOX_MANAGED=true).
pub async fn run(state: AppState) {
    if !state.cfg.singbox_managed {
        return;
    }
    let path = {
        let p = state.cfg.self_singbox_config_path.trim();
        if p.is_empty() { DEFAULT_CONFIG_PATH.to_string() } else { p.to_string() }
    };
    let interval = Duration::from_secs(state.cfg.self_singbox_interval);
    info!(
        "sing-box supervisor enabled: bin={} config={path} (every {}s)",
        state.cfg.singbox_bin, state.cfg.self_singbox_interval
    );

    let mut sb = Singbox::new(state.cfg.singbox_bin.clone(), path);
    let mut last_etag = String::new();
    loop {
        if let Some((etag, config_str)) = render_self(&state).await {
            if etag != last_etag {
                match sb.apply(&config_str).await {
                    Ok(_) => last_etag = etag,
                    Err(e) => error!("sing-box config write failed: {e}"),
                }
            }
        }
        sb.ensure_alive();
        tokio::time::sleep(interval).await;
    }
}
