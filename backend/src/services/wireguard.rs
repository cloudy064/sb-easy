//! WireGuard management — pure Rust key generation + kernel-native CLI.
//!
//! Keys: x25519-dalek (no external tools).
//! Interface: `ip link` / `wg` (built into every Linux kernel).
//!
//! On non-Linux: key generation works; interface ops return errors gracefully.

use base64::Engine;
use rand::rngs::OsRng;
use std::process::Command;
use tracing::{info, warn};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::config::Config;
use crate::error::{AppError, Result};
use crate::models::wireguard::{PeerStats, WireGuardPeer};

// ── x25519 Key generation (pure Rust, works everywhere) ─────

pub fn generate_keypair() -> Result<(String, String)> {
    let secret = StaticSecret::random_from_rng(OsRng);
    let private = base64::engine::general_purpose::STANDARD.encode(secret.as_bytes());
    let public_key = PublicKey::from(&secret);
    let public = base64::engine::general_purpose::STANDARD.encode(public_key.as_bytes());
    Ok((private, public))
}

pub fn generate_psk() -> Result<String> {
    let secret = StaticSecret::random_from_rng(OsRng);
    Ok(base64::engine::general_purpose::STANDARD.encode(secret.as_bytes()))
}

pub fn public_key_from_private(private_b64: &str) -> Result<String> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(private_b64)
        .map_err(|_| AppError::BadRequest("Invalid WireGuard key".into()))?;
    let arr: [u8; 32] = bytes.try_into()
        .map_err(|_| AppError::BadRequest("WireGuard key must be 32 bytes".into()))?;
    let secret = StaticSecret::from(arr);
    let public = PublicKey::from(&secret);
    Ok(base64::engine::general_purpose::STANDARD.encode(public.as_bytes()))
}

// ── Lifecycle ───────────────────────────────────────────────

pub struct WireGuardGuard;

pub async fn startup(pool: &sqlx::SqlitePool, cfg: &Config) -> Result<WireGuardGuard> {
    #[cfg(not(target_os = "linux"))]
    {
        warn!("WireGuard: not on Linux — interface management disabled");
        return Ok(WireGuardGuard);
    }

    #[cfg(target_os = "linux")]
    {
        // 1. Load/generate server keypair
        let private_key = load_or_generate_server_key(pool).await?;
        let public_key = public_key_from_private(&private_key).unwrap_or_default();
        info!("Server public key: {public_key}");

        // 2. Generate wg conf from DB
        let conf = build_wg_conf(pool, cfg, &private_key).await?;
        let conf_path = format!("/etc/wireguard/{}.conf", cfg.wg_interface);

        // Write config
        std::fs::create_dir_all("/etc/wireguard").ok();
        std::fs::write(&conf_path, &conf)
            .map_err(|e| AppError::Internal(format!("write {}: {e}", conf_path)))?;

        // 3. Bring up interface (idempotent — wg-quick handles both create and reconfigure)
        if interface_exists(cfg) {
            info!("Interface {} exists — syncing config via wg syncconf", cfg.wg_interface);
            run_cmd("wg", &["syncconf", &cfg.wg_interface, &conf_path])?;
        } else {
            info!("Creating WireGuard interface {}...", cfg.wg_interface);
            run_cmd("ip", &["link", "add", &cfg.wg_interface, "type", "wireguard"])?;
            run_cmd("ip", &["address", "add", &cfg.wg_address, "dev", &cfg.wg_interface])?;
            run_cmd("ip", &["link", "set", "up", &cfg.wg_interface])?;
            run_cmd("wg", &["setconf", &cfg.wg_interface, &conf_path])?;

            // Apply post-up iptables rules
            if !cfg.wg_post_up.is_empty() {
                run_cmd("sh", &["-c", &cfg.wg_post_up])?;
            }
            info!("WireGuard interface {} is UP", cfg.wg_interface);
        }

        Ok(WireGuardGuard)
    }
}

pub async fn shutdown(cfg: &Config) {
    #[cfg(not(target_os = "linux"))]
    { return; }

    #[cfg(target_os = "linux")]
    {
        // Post-down iptables
        if !cfg.wg_post_down.is_empty() {
            run_cmd("sh", &["-c", &cfg.wg_post_down]).ok();
        }
        if interface_exists(cfg) {
            info!("Removing WireGuard interface {}...", cfg.wg_interface);
            run_cmd("ip", &["link", "delete", &cfg.wg_interface]).ok();
        }
    }
}

// ── Peer sync ───────────────────────────────────────────────

pub async fn sync_config(pool: &sqlx::SqlitePool, cfg: &Config) -> Result<()> {
    let private_key = load_or_generate_server_key(pool).await?;
    let conf = build_wg_conf(pool, cfg, &private_key).await?;
    let conf_path = format!("/etc/wireguard/{}.conf", cfg.wg_interface);
    std::fs::write(&conf_path, &conf).map_err(|e| AppError::Internal(e.to_string()))?;
    run_cmd("wg", &["syncconf", &cfg.wg_interface, &conf_path])?;

    let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM wireguard_peers WHERE enabled = 1")
        .fetch_one(pool).await?;
    info!("WireGuard synced ({count} peers)");
    Ok(())
}

// ── Stats ───────────────────────────────────────────────────

pub fn get_peer_stats(interface: &str) -> Result<Vec<PeerStats>> {
    let output = Command::new("wg").args(["show", interface, "dump"]).output()
        .map_err(|e| AppError::Internal(e.to_string()))?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut stats = Vec::new();

    for line in stdout.lines() {
        let fields: Vec<&str> = line.split('\t').collect();
        if fields.len() >= 8 {
            stats.push(PeerStats {
                public_key: fields[0].to_string(),
                endpoint: if fields[2].is_empty() || fields[2] == "(none)" {
                    None
                } else {
                    Some(fields[2].to_string())
                },
                latest_handshake: fields[4].parse::<i64>().ok().filter(|&t| t > 0),
                transfer_rx: fields[5].parse::<i64>().unwrap_or(0),
                transfer_tx: fields[6].parse::<i64>().unwrap_or(0),
            });
        }
    }
    Ok(stats)
}

// ── Peer removal ────────────────────────────────────────────

pub fn remove_peer(interface: &str, public_key: &str) -> Result<()> {
    run_cmd("wg", &["set", interface, "peer", public_key, "remove"])
}

// ── Client config ───────────────────────────────────────────

pub fn generate_client_config(cfg: &Config, peer: &WireGuardPeer, server_pubkey: &str) -> Result<String> {
    let mut c = String::new();
    c.push_str(&format!("# Client: {}\n[Interface]\n", peer.name));
    c.push_str(&format!("PrivateKey = {}\n", peer.private_key));
    c.push_str(&format!("Address = {}\n", peer.address));
    c.push_str(&format!("DNS = {}\n", peer.dns));
    if cfg.wg_mtu > 0 { c.push_str(&format!("MTU = {}\n", cfg.wg_mtu)); }
    c.push_str("\n[Peer]\n");
    c.push_str(&format!("PublicKey = {}\n", server_pubkey));
    if let Some(ref psk) = peer.preshared_key {
        if !psk.is_empty() { c.push_str(&format!("PresharedKey = {}\n", psk)); }
    }
    c.push_str(&format!("AllowedIPs = {}\n", peer.allowed_ips));
    c.push_str(&format!("Endpoint = {}:{}\n", cfg.external_hostname, cfg.wg_port));
    if peer.persistent_keepalive > 0 {
        c.push_str(&format!("PersistentKeepalive = {}\n", peer.persistent_keepalive));
    }
    Ok(c)
}

// ── IP pool ─────────────────────────────────────────────────

pub async fn next_available_ip(pool: &sqlx::SqlitePool, subnet: &str) -> Result<String> {
    let base = subnet.rsplitn(2, '.').last().unwrap_or("10.59.32");
    let existing: Vec<(String,)> = sqlx::query_as("SELECT address FROM wireguard_peers")
        .fetch_all(pool).await.unwrap_or_default();
    for i in 2..=254 {
        let prefix = format!("{base}.{i}");
        if !existing.iter().any(|(a,)| a.starts_with(&prefix)) {
            return Ok(format!("{prefix}/24"));
        }
    }
    Err(AppError::Internal("No available IPs in subnet".into()))
}

// ── Server key (persisted in DB) ────────────────────────────

pub async fn load_or_generate_server_key(pool: &sqlx::SqlitePool) -> Result<String> {
    let row: Option<(String,)> = sqlx::query_as(
        "SELECT value FROM app_settings WHERE key = 'wg_server_key'"
    ).fetch_optional(pool).await?;

    if let Some((value,)) = row {
        let parsed: serde_json::Value = serde_json::from_str(&value).unwrap_or_default();
        if let Some(key) = parsed["private_key"].as_str() {
            if !key.is_empty() { return Ok(key.to_string()); }
        }
    }

    let (private, public) = generate_keypair()?;
    info!("Generated new WireGuard server keypair (public: {public})");

    let j = serde_json::json!({"private_key": private, "public_key": public});
    sqlx::query(
        "INSERT INTO app_settings (key, value, updated_at) VALUES ('wg_server_key', ?, datetime('now'))
         ON CONFLICT(key) DO UPDATE SET value = ?, updated_at = datetime('now')"
    )
    .bind(serde_json::to_string(&j).unwrap_or_default())
    .bind(serde_json::to_string(&j).unwrap_or_default())
    .execute(pool).await?;

    Ok(private)
}

pub fn get_server_private_key(_cfg: &Config) -> Result<String> {
    // Try reading from running wg0 interface
    let output = Command::new("wg").args(["show", "wg0", "private-key"]).output();
    if let Ok(o) = output {
        if o.status.success() {
            let s = String::from_utf8_lossy(&o.stdout).trim().to_string();
            if !s.is_empty() { return Ok(s); }
        }
    }
    // Fallback to generated keys
    let (private, _) = generate_keypair()?;
    Ok(private)
}

// ── Internal helpers ────────────────────────────────────────

async fn build_wg_conf(pool: &sqlx::SqlitePool, cfg: &Config, private_key: &str) -> Result<String> {
    let peers = sqlx::query_as::<_, WireGuardPeer>(
        "SELECT * FROM wireguard_peers WHERE enabled = 1"
    ).fetch_all(pool).await?;

    let mut conf = String::from("# Generated by sb-easy\n\n[Interface]\n");
    conf.push_str(&format!("PrivateKey = {}\n", private_key));
    conf.push_str(&format!("Address = {}\n", cfg.wg_address));
    conf.push_str(&format!("ListenPort = {}\n", cfg.wg_port));
    if cfg.wg_mtu > 0 { conf.push_str(&format!("MTU = {}\n", cfg.wg_mtu)); }
    if !cfg.wg_post_up.is_empty() {
        conf.push_str(&format!("PostUp = {}\n", cfg.wg_post_up));
    }
    if !cfg.wg_post_down.is_empty() {
        conf.push_str(&format!("PostDown = {}\n", cfg.wg_post_down));
    }

    for peer in &peers {
        conf.push_str(&format!("\n# Client: {}\n[Peer]\nPublicKey = {}\n", peer.name, peer.public_key));
        if let Some(ref psk) = peer.preshared_key {
            if !psk.is_empty() { conf.push_str(&format!("PresharedKey = {}\n", psk)); }
        }
        conf.push_str(&format!("AllowedIPs = {}\n", peer.address));
        if peer.persistent_keepalive > 0 {
            conf.push_str(&format!("PersistentKeepalive = {}\n", peer.persistent_keepalive));
        }
    }
    Ok(conf)
}

fn interface_exists(cfg: &Config) -> bool {
    Command::new("ip")
        .args(["link", "show", &cfg.wg_interface])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn run_cmd(cmd: &str, args: &[&str]) -> Result<()> {
    let output = Command::new(cmd)
        .args(args)
        .output()
        .map_err(|e| AppError::Internal(format!("{cmd}: {e}")))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        warn!("{cmd} {:?}: {stderr}", args);
    }
    Ok(())
}
