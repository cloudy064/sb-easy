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
        let rt = load_wg_runtime(pool, cfg).await;

        // 1. Load/generate server keypair
        let private_key = load_or_generate_server_key(pool).await?;
        let public_key = public_key_from_private(&private_key).unwrap_or_default();
        info!("Server public key: {public_key}");

        // 2. Generate wg conf from DB
        let conf = build_wg_conf(pool, cfg, &private_key, &rt).await?;
        let conf_path = format!("/etc/wireguard/{}.conf", rt.interface);

        // Write config
        std::fs::create_dir_all("/etc/wireguard").ok();
        std::fs::write(&conf_path, &conf)
            .map_err(|e| AppError::Internal(format!("write {}: {e}", conf_path)))?;

        // 3. Bring up interface
        if interface_exists_by_name(&rt.interface) {
            info!("Interface {} exists — syncing config via wg syncconf", rt.interface);
            run_cmd("wg", &["syncconf", &rt.interface, &conf_path])?;
        } else {
            info!("Creating WireGuard interface {}...", rt.interface);
            run_cmd("ip", &["link", "add", &rt.interface, "type", "wireguard"])?;
            if rt.mtu > 0 {
                let mtu_s = rt.mtu.to_string();
                run_cmd("ip", &["link", "set", &rt.interface, "mtu", &mtu_s])?;
            }
            run_cmd("ip", &["address", "add", &rt.address, "dev", &rt.interface])?;
            run_cmd("ip", &["link", "set", "up", &rt.interface])?;
            run_cmd("wg", &["setconf", &rt.interface, &conf_path])?;
            info!("WireGuard interface {} is UP", rt.interface);
        }

        // NAT/forwarding: fixed internal rules derived from config (replaces the
        // old arbitrary WG_POST_UP shell, which was an RCE surface).
        setup_nat(&rt.interface, &rt.address);

        Ok(WireGuardGuard)
    }
}

pub async fn shutdown(pool: &sqlx::SqlitePool, cfg: &Config) {
    #[cfg(not(target_os = "linux"))]
    { return; }

    #[cfg(target_os = "linux")]
    {
        let rt = load_wg_runtime(pool, cfg).await;
        teardown_nat(&rt.interface, &rt.address);
        if interface_exists_by_name(&rt.interface) {
            info!("Removing WireGuard interface {}...", rt.interface);
            run_cmd("ip", &["link", "delete", &rt.interface]).ok();
        }
    }
}

/// Configure NAT masquerade + forwarding for the WireGuard subnet using fixed,
/// internally-constructed iptables rules. The egress interface is auto-detected
/// from the default route (override with WG_EGRESS). No shell interpolation.
#[cfg(target_os = "linux")]
fn setup_nat(interface: &str, address: &str) {
    let subnet = match subnet_cidr(address) {
        Some(s) => s,
        None => {
            warn!("NAT skipped: could not derive subnet from {address}");
            return;
        }
    };
    let egress = egress_interface();
    run_cmd("sysctl", &["-w", "net.ipv4.ip_forward=1"]).ok();
    // -C checks existence; only add when missing to stay idempotent.
    if run_cmd_ok("iptables", &["-t", "nat", "-C", "POSTROUTING", "-s", &subnet, "-o", &egress, "-j", "MASQUERADE"]).is_err() {
        run_cmd("iptables", &["-t", "nat", "-A", "POSTROUTING", "-s", &subnet, "-o", &egress, "-j", "MASQUERADE"]).ok();
    }
    if run_cmd_ok("iptables", &["-C", "FORWARD", "-i", interface, "-j", "ACCEPT"]).is_err() {
        run_cmd("iptables", &["-A", "FORWARD", "-i", interface, "-j", "ACCEPT"]).ok();
    }
    if run_cmd_ok("iptables", &["-C", "FORWARD", "-o", interface, "-j", "ACCEPT"]).is_err() {
        run_cmd("iptables", &["-A", "FORWARD", "-o", interface, "-j", "ACCEPT"]).ok();
    }
    info!("NAT configured: {subnet} → {egress} (masquerade)");
}

#[cfg(target_os = "linux")]
fn teardown_nat(interface: &str, address: &str) {
    let Some(subnet) = subnet_cidr(address) else { return };
    let egress = egress_interface();
    run_cmd("iptables", &["-t", "nat", "-D", "POSTROUTING", "-s", &subnet, "-o", &egress, "-j", "MASQUERADE"]).ok();
    run_cmd("iptables", &["-D", "FORWARD", "-i", interface, "-j", "ACCEPT"]).ok();
    run_cmd("iptables", &["-D", "FORWARD", "-o", interface, "-j", "ACCEPT"]).ok();
}

/// Derive the network CIDR ("10.59.32.1/24" → "10.59.32.0/24").
#[cfg(target_os = "linux")]
fn subnet_cidr(address: &str) -> Option<String> {
    let (host, prefix) = address.split_once('/')?;
    let mut octets: Vec<&str> = host.split('.').collect();
    if octets.len() != 4 {
        return None;
    }
    // Zero host bits only for the common /24 case; otherwise keep the given host.
    if prefix == "24" {
        octets[3] = "0";
    }
    Some(format!("{}/{}", octets.join("."), prefix))
}

/// Detect the egress interface: WG_EGRESS env override, else the default route's
/// device, else "eth0".
#[cfg(target_os = "linux")]
fn egress_interface() -> String {
    if let Ok(v) = std::env::var("WG_EGRESS") {
        if !v.trim().is_empty() {
            return v;
        }
    }
    if let Ok(out) = Command::new("ip").args(["route", "show", "default"]).output() {
        let s = String::from_utf8_lossy(&out.stdout);
        // "default via X dev eth0 ..."
        if let Some(idx) = s.split_whitespace().position(|t| t == "dev") {
            if let Some(dev) = s.split_whitespace().nth(idx + 1) {
                return dev.to_string();
            }
        }
    }
    "eth0".to_string()
}

/// Like run_cmd but returns Err when the command exits non-zero (used for the
/// iptables `-C` existence checks).
#[cfg(target_os = "linux")]
fn run_cmd_ok(cmd: &str, args: &[&str]) -> Result<()> {
    let output = Command::new(cmd)
        .args(args)
        .output()
        .map_err(|e| AppError::Internal(format!("{cmd}: {e}")))?;
    if output.status.success() {
        Ok(())
    } else {
        Err(AppError::Internal(format!("{cmd} exited non-zero")))
    }
}

// ── Peer sync ───────────────────────────────────────────────

/// Reconcile DB settings + env config into effective WG parameters.
/// app_settings in the DB take priority (set via UI), env vars are fallback.
struct WgRuntime {
    interface: String,
    port: u16,
    address: String,
    #[allow(dead_code)]
    dns: String,
    mtu: u32,
}

async fn load_wg_runtime(pool: &sqlx::SqlitePool, cfg: &Config) -> WgRuntime {
    let db: Option<(String,)> = sqlx::query_as(
        "SELECT value FROM app_settings WHERE key = 'wireguard_interface'"
    ).fetch_optional(pool).await.ok().flatten();

    let db_val = db.as_ref()
        .and_then(|(v,)| serde_json::from_str::<serde_json::Value>(v).ok());

    WgRuntime {
        interface: str_or(db_val.as_ref(), "interface", &cfg.wg_interface),
        port: u16_or(db_val.as_ref(), "listen_port", cfg.wg_port),
        address: str_or(db_val.as_ref(), "address", &cfg.wg_address),
        dns: str_or(db_val.as_ref(), "dns", &cfg.wg_dns),
        mtu: u32_or(db_val.as_ref(), "mtu", cfg.wg_mtu),
    }
}

fn str_or(db: Option<&serde_json::Value>, key: &str, fallback: &str) -> String {
    db.and_then(|v| v.get(key).and_then(|v| v.as_str())).unwrap_or(fallback).to_string()
}
fn u16_or(db: Option<&serde_json::Value>, key: &str, fallback: u16) -> u16 {
    db.and_then(|v| v.get(key).and_then(|v| v.as_u64())).map(|n| n as u16).unwrap_or(fallback)
}
fn u32_or(db: Option<&serde_json::Value>, key: &str, fallback: u32) -> u32 {
    db.and_then(|v| v.get(key).and_then(|v| v.as_u64())).map(|n| n as u32).unwrap_or(fallback)
}

pub async fn sync_config(pool: &sqlx::SqlitePool, cfg: &Config) -> Result<()> {
    let rt = load_wg_runtime(pool, cfg).await;
    sync_config_with(pool, cfg, &rt).await
}

async fn sync_config_with(pool: &sqlx::SqlitePool, cfg: &Config, rt: &WgRuntime) -> Result<()> {
    let private_key = load_or_generate_server_key(pool).await?;
    let conf = build_wg_conf(pool, cfg, &private_key, rt).await?;
    let conf_path = format!("/etc/wireguard/{}.conf", rt.interface);
    std::fs::write(&conf_path, &conf).map_err(|e| AppError::Internal(e.to_string()))?;
    run_cmd("wg", &["syncconf", &rt.interface, &conf_path])?;

    let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM wireguard_peers WHERE enabled = 1")
        .fetch_one(pool).await?;
    info!("WireGuard synced ({} peers)", count.0);
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

// ── Managed-host peers (intranet members for reachback) ─────
//
// A WG-member Host is provisioned as a special peer: stored with a /32 address
// so the server side gets `AllowedIPs = <ip>/32` and can route precisely to that
// host (needed to reach its Clash API over the tunnel). End-user clients keep
// their broader address; host peers carry `host_id` to distinguish them.

/// Derive the WG subnet CIDR from the server address ("10.59.32.1/24" →
/// "10.59.32.0/24"). Used as a host's AllowedIPs so it routes the intranet
/// (not all traffic) through the hub.
pub fn wg_subnet(address: &str) -> String {
    if let Some((host, prefix)) = address.split_once('/') {
        let mut o: Vec<&str> = host.split('.').collect();
        if o.len() == 4 && prefix == "24" {
            o[3] = "0";
            return format!("{}/{}", o.join("."), prefix);
        }
        return format!("{host}/{prefix}");
    }
    address.to_string()
}

/// Ensure a WG peer exists for this host; returns `(ip, public_key)`. Idempotent:
/// if one already exists it is returned unchanged.
pub async fn provision_host_peer(
    pool: &sqlx::SqlitePool,
    cfg: &Config,
    host_id: &str,
    host_name: &str,
) -> Result<(String, String)> {
    use uuid::Uuid;

    if let Some(p) = sqlx::query_as::<_, WireGuardPeer>("SELECT * FROM wireguard_peers WHERE host_id = ?")
        .bind(host_id)
        .fetch_optional(pool)
        .await?
    {
        let ip = p.address.split('/').next().unwrap_or(&p.address).to_string();
        return Ok((ip, p.public_key));
    }

    let (private_key, public_key) = generate_keypair()?;
    let preshared_key = generate_psk()?;
    let alloc = next_available_ip(pool, &cfg.wg_address).await?;
    let ip = alloc.split('/').next().unwrap_or(&alloc).to_string();
    let address = format!("{ip}/32");
    let subnet = wg_subnet(&cfg.wg_address);
    let id = Uuid::new_v4().to_string();
    let now = chrono::Utc::now().to_rfc3339();

    sqlx::query(
        "INSERT INTO wireguard_peers (id, name, private_key, public_key, preshared_key, address, dns, enabled, persistent_keepalive, allowed_ips, expire_at, quota_bytes, created_at, updated_at, notes, host_id) \
         VALUES (?,?,?,?,?,?,?,1,25,?,NULL,0,?,?,NULL,?)",
    )
    .bind(&id)
    .bind(format!("host: {host_name}"))
    .bind(&private_key)
    .bind(&public_key)
    .bind(&preshared_key)
    .bind(&address)
    .bind("")
    .bind(&subnet)
    .bind(&now)
    .bind(&now)
    .bind(host_id)
    .execute(pool)
    .await?;

    let _ = sync_config(pool, cfg).await;
    Ok((ip, public_key))
}

/// Remove the WG peer backing a host (on host delete or when WG membership is
/// turned off). Best-effort; safe when no peer exists.
pub async fn deprovision_host_peer(pool: &sqlx::SqlitePool, cfg: &Config, host_id: &str) {
    if let Ok(Some(p)) = sqlx::query_as::<_, WireGuardPeer>("SELECT * FROM wireguard_peers WHERE host_id = ?")
        .bind(host_id)
        .fetch_optional(pool)
        .await
    {
        remove_peer(&cfg.wg_interface, &p.public_key).ok();
        let _ = sqlx::query("DELETE FROM wireguard_peers WHERE id = ?").bind(&p.id).execute(pool).await;
        let _ = sync_config(pool, cfg).await;
    }
}

/// Generate the WG config a managed host installs. Unlike a client config it
/// routes only the intranet subnet (AllowedIPs = WG subnet), not all traffic.
pub async fn generate_host_wg_config(pool: &sqlx::SqlitePool, cfg: &Config, host_id: &str) -> Result<String> {
    let peer = sqlx::query_as::<_, WireGuardPeer>("SELECT * FROM wireguard_peers WHERE host_id = ?")
        .bind(host_id)
        .fetch_optional(pool)
        .await?
        .ok_or_else(|| AppError::NotFound("Host has no WireGuard peer".into()))?;

    let server_pubkey = load_or_generate_server_key(pool)
        .await
        .and_then(|pk| public_key_from_private(&pk))
        .unwrap_or_else(|_| "UNKNOWN".into());
    let subnet = wg_subnet(&cfg.wg_address);

    let label = peer.name.strip_prefix("host: ").unwrap_or(&peer.name);
    let mut c = String::new();
    c.push_str(&format!("# sb-easy managed host: {}\n[Interface]\n", label));
    c.push_str(&format!("PrivateKey = {}\n", peer.private_key));
    c.push_str(&format!("Address = {}\n", peer.address));
    if cfg.wg_mtu > 0 {
        c.push_str(&format!("MTU = {}\n", cfg.wg_mtu));
    }
    c.push_str("\n[Peer]\n");
    c.push_str(&format!("PublicKey = {}\n", server_pubkey));
    if let Some(ref psk) = peer.preshared_key {
        if !psk.is_empty() {
            c.push_str(&format!("PresharedKey = {}\n", psk));
        }
    }
    c.push_str(&format!("AllowedIPs = {}\n", subnet));
    c.push_str(&format!("Endpoint = {}:{}\n", cfg.external_hostname, cfg.wg_port));
    c.push_str("PersistentKeepalive = 25\n");
    Ok(c)
}

// ── IP pool ─────────────────────────────────────────────────

pub async fn next_available_ip(pool: &sqlx::SqlitePool, subnet: &str) -> Result<String> {
    // subnet looks like "10.59.32.1/24" — derive the /24 base ("10.59.32").
    let host = subnet.split('/').next().unwrap_or(subnet);
    let base = host.rsplit_once('.').map(|(b, _)| b).unwrap_or("10.59.32");

    // Collect the host octets already taken in this /24.
    let existing: Vec<(String,)> = sqlx::query_as("SELECT address FROM wireguard_peers")
        .fetch_all(pool).await.unwrap_or_default();
    let taken: std::collections::HashSet<u8> = existing
        .iter()
        .filter_map(|(a,)| {
            let h = a.split('/').next().unwrap_or(a);
            let (b, last) = h.rsplit_once('.')?;
            if b == base { last.parse::<u8>().ok() } else { None }
        })
        .collect();

    for i in 2u8..=254 {
        if !taken.contains(&i) {
            return Ok(format!("{base}.{i}/24"));
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

async fn build_wg_conf(pool: &sqlx::SqlitePool, _cfg: &Config, private_key: &str, rt: &WgRuntime) -> Result<String> {
    let peers = sqlx::query_as::<_, WireGuardPeer>(
        "SELECT * FROM wireguard_peers WHERE enabled = 1"
    ).fetch_all(pool).await?;

    let mut conf = String::from("# Generated by sb-easy\n\n[Interface]\n");
    conf.push_str(&format!("PrivateKey = {}\n", private_key));
    conf.push_str(&format!("ListenPort = {}\n", rt.port));

    let now = chrono::Utc::now();
    let stats = get_peer_stats(&rt.interface).unwrap_or_default();
    for peer in &peers {
        // Skip peers whose expiry has passed — enabled but expired peers stay in
        // the DB (visible in the UI) but are not written into the live config.
        if peer_expired(peer, now) {
            continue;
        }
        // Skip peers that have exhausted their traffic quota (0 = unlimited).
        if peer.quota_bytes > 0 {
            if let Some(s) = stats.iter().find(|s| s.public_key == peer.public_key) {
                if s.transfer_rx + s.transfer_tx >= peer.quota_bytes {
                    continue;
                }
            }
        }
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

/// True if the peer has an `expire_at` timestamp that is in the past.
pub fn peer_expired(peer: &WireGuardPeer, now: chrono::DateTime<chrono::Utc>) -> bool {
    match peer.expire_at.as_deref() {
        Some(ts) if !ts.is_empty() => chrono::DateTime::parse_from_rfc3339(ts)
            .map(|t| t.with_timezone(&chrono::Utc) < now)
            .unwrap_or(false),
        _ => false,
    }
}

fn interface_exists_by_name(name: &str) -> bool {
    Command::new("ip")
        .args(["link", "show", name])
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
        let err = String::from_utf8_lossy(&output.stderr);
        warn!("{cmd} {:?}: {err}", args);
    }
    Ok(())
}
