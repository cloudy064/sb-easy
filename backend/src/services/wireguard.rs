//! WireGuard management.
//! Linux: uses netlink to talk directly to the kernel module (no CLI tools).
//! Other platforms: key generation works everywhere; interface ops return errors.

use base64::Engine;
use rand::rngs::OsRng;
use tracing::{info, warn};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::config::Config;
use crate::error::{AppError, Result};
use crate::models::wireguard::{PeerStats, WireGuardPeer};

// ── Key generation (x25519 pure Rust — works everywhere) ────

pub fn generate_private_key() -> String {
    let secret = StaticSecret::random_from_rng(OsRng);
    base64::engine::general_purpose::STANDARD.encode(secret.as_bytes())
}

pub fn public_key_from_private(private_b64: &str) -> Result<String> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(private_b64)
        .map_err(|e| AppError::BadRequest(format!("Invalid WireGuard key: {e}")))?;
    let arr: [u8; 32] = bytes.try_into()
        .map_err(|_| AppError::BadRequest("WireGuard key must be 32 bytes".into()))?;
    let secret = StaticSecret::from(arr);
    let public = PublicKey::from(&secret);
    Ok(base64::engine::general_purpose::STANDARD.encode(public.as_bytes()))
}

pub fn generate_preshared_key() -> String {
    let secret = StaticSecret::random_from_rng(OsRng);
    base64::engine::general_purpose::STANDARD.encode(secret.as_bytes())
}

pub fn generate_keypair() -> Result<(String, String)> {
    let private = generate_private_key();
    let public = public_key_from_private(&private).unwrap_or_default();
    Ok((private, public))
}

pub fn generate_psk() -> Result<String> {
    Ok(generate_preshared_key())
}

// ── Lifecycle ───────────────────────────────────────────────

#[cfg(target_os = "linux")]
pub async fn startup(pool: &sqlx::SqlitePool, cfg: &Config) -> Result<WireGuardGuard> {
    linux::startup(pool, cfg).await
}

#[cfg(not(target_os = "linux"))]
pub async fn startup(_pool: &sqlx::SqlitePool, _cfg: &Config) -> Result<WireGuardGuard> {
    warn!("WireGuard kernel interface unavailable — not running on Linux.");
    warn!("Deploy to Linux for full WireGuard management. Key generation works everywhere.");
    Ok(WireGuardGuard)
}

/// Guard token — empty on non-Linux, holds the interface lifecycle on Linux.
pub struct WireGuardGuard;

#[cfg(target_os = "linux")]
pub async fn shutdown(cfg: &Config) {
    linux::shutdown(cfg).await;
}

#[cfg(not(target_os = "linux"))]
pub async fn shutdown(_cfg: &Config) {}

// ── Sync ────────────────────────────────────────────────────

#[cfg(target_os = "linux")]
pub async fn sync_config(pool: &sqlx::SqlitePool, cfg: &Config) -> Result<()> {
    linux::sync_config(pool, cfg).await
}

#[cfg(not(target_os = "linux"))]
pub async fn sync_config(_pool: &sqlx::SqlitePool, cfg: &Config) -> Result<()> {
    warn!("Cannot sync WireGuard — not running on Linux");
    Ok(())
}

// ── Stats ───────────────────────────────────────────────────

#[cfg(target_os = "linux")]
pub fn get_peer_stats(interface: &str) -> Result<Vec<PeerStats>> {
    linux::get_peer_stats(interface)
}

#[cfg(not(target_os = "linux"))]
pub fn get_peer_stats(_interface: &str) -> Result<Vec<PeerStats>> {
    Ok(Vec::new())
}

// ── Peer removal ────────────────────────────────────────────

#[cfg(target_os = "linux")]
pub fn remove_peer(interface: &str, public_key: &str) -> Result<()> {
    linux::remove_peer(interface, public_key)
}

#[cfg(not(target_os = "linux"))]
pub fn remove_peer(_interface: &str, _public_key: &str) -> Result<()> {
    warn!("Cannot remove peer — not running on Linux");
    Ok(())
}

// ── Client config ───────────────────────────────────────────

pub fn generate_client_config(cfg: &Config, peer: &WireGuardPeer, server_public_key: &str) -> Result<String> {
    let mut conf = String::new();
    conf.push_str(&format!("# Client: {}\n", peer.name));
    conf.push_str("[Interface]\n");
    conf.push_str(&format!("PrivateKey = {}\n", peer.private_key));
    conf.push_str(&format!("Address = {}\n", peer.address));
    conf.push_str(&format!("DNS = {}\n", peer.dns));
    if cfg.wg_mtu > 0 { conf.push_str(&format!("MTU = {}\n", cfg.wg_mtu)); }
    conf.push_str("\n[Peer]\n");
    conf.push_str(&format!("PublicKey = {}\n", server_public_key));
    if let Some(ref psk) = peer.preshared_key {
        if !psk.is_empty() { conf.push_str(&format!("PresharedKey = {}\n", psk)); }
    }
    conf.push_str(&format!("AllowedIPs = {}\n", peer.allowed_ips));
    conf.push_str(&format!("Endpoint = {}:{}\n", cfg.external_hostname, cfg.wg_port));
    if peer.persistent_keepalive > 0 {
        conf.push_str(&format!("PersistentKeepalive = {}\n", peer.persistent_keepalive));
    }
    Ok(conf)
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
    Err(AppError::Internal("No available IPs".into()))
}

// ── Server key (DB-persisted) ──────────────────────────────

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
    Ok(String::new())
}

// ── Linux-specific implementation ────────────────────────────

#[cfg(target_os = "linux")]
mod linux {
    use netlink_packet_route::address::AddressAttribute;
    use netlink_packet_route::link::{InfoKind, LinkAttribute, LinkInfo, LinkMessage};
    use rtnetlink::new_connection;
    use std::net::Ipv4Addr;
    use std::str::FromStr;
    use tracing::{info, warn};

    use crate::config::Config;
    use crate::error::{AppError, Result};
    use crate::models::wireguard::{PeerStats, WireGuardPeer};
    use super::super::wireguard_nl as nl;

    pub async fn startup(pool: &sqlx::SqlitePool, cfg: &Config) -> Result<super::WireGuardGuard> {
        let (conn, handle, _) = new_connection().map_err(|e| AppError::Internal(e.to_string()))?;
        tokio::spawn(conn);

        let private_key = super::load_or_generate_server_key(pool).await?;
        let public_key = super::public_key_from_private(&private_key).unwrap_or_default();
        info!("Server public key: {public_key}");

        let ifindex = get_ifindex(&handle, &cfg.wg_interface).await;

        if let Some(idx) = ifindex {
            info!("Interface {} (ifindex={idx}) exists — syncing config", cfg.wg_interface);
        } else {
            info!("Creating WireGuard interface {}...", cfg.wg_interface);
            create_wg_iface(&handle, &cfg.wg_interface).await?;
            let idx = get_ifindex(&handle, &cfg.wg_interface).await
                .ok_or_else(|| AppError::Internal("ifindex not found".into()))?;
            set_ip(&handle, idx, &cfg.wg_address).await?;
            bring_up(&handle, idx).await?;
            info!("Interface {} is UP", cfg.wg_interface);
            if !cfg.wg_post_up.is_empty() {
                let _ = std::process::Command::new("sh").arg("-c").arg(&cfg.wg_post_up).output();
            }
        }

        sync_config(pool, cfg).await?;
        Ok(super::WireGuardGuard)
    }

    pub async fn shutdown(cfg: &Config) {
        let (conn, handle, _) = match new_connection() {
            Ok(c) => c, Err(_) => return
        };
        tokio::spawn(conn);
        if !cfg.wg_post_down.is_empty() {
            let _ = std::process::Command::new("sh").arg("-c").arg(&cfg.wg_post_down).output();
        }
        if let Some(idx) = get_ifindex(&handle, &cfg.wg_interface).await {
            let mut msg = LinkMessage::default();
            msg.header.index = idx;
            handle.link().delete(msg).execute().await.ok();
        }
    }

    pub async fn sync_config(pool: &sqlx::SqlitePool, cfg: &Config) -> Result<()> {
        let (conn, handle, _) = new_connection().map_err(|e| AppError::Internal(e.to_string()))?;
        tokio::spawn(conn);
        let ifindex = get_ifindex(&handle, &cfg.wg_interface).await
            .ok_or_else(|| AppError::Internal("interface not found".into()))?;
        let peers = sqlx::query_as::<_, WireGuardPeer>(
            "SELECT * FROM wireguard_peers WHERE enabled = 1"
        ).fetch_all(pool).await?;
        let private_key = super::load_or_generate_server_key(pool).await?;

        let configs: Vec<nl::WgPeerConfig> = peers.iter().map(|p| nl::WgPeerConfig {
            public_key: p.public_key.clone(),
            preshared_key: p.preshared_key.clone(),
            persistent_keepalive: p.persistent_keepalive as u16,
            allowed_ips: p.allowed_ips.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect(),
            remove: false,
            replace_allowed_ips: true,
        }).collect();

        nl::set_device(ifindex, Some(&private_key), cfg.wg_port, true, &configs)?;
        info!("WireGuard synced ({} peers)", configs.len());
        Ok(())
    }

    pub fn get_peer_stats(interface: &str) -> Result<Vec<PeerStats>> {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let ifindex = rt.block_on(async {
            let (conn, handle, _) = new_connection().ok()?;
            tokio::spawn(conn);
            get_ifindex(&handle, interface).await
        }).ok_or_else(|| AppError::Internal("interface not found".into()))?;

        let device = nl::get_device(ifindex).unwrap_or_else(|_| nl::WgDeviceInfo {
            ifindex: 0, ifname: String::new(), public_key: String::new(), listen_port: 0, peers: vec![]
        });

        Ok(device.peers.iter().map(|p| PeerStats {
            public_key: p.public_key.clone(),
            endpoint: p.endpoint.clone(),
            latest_handshake: if p.latest_handshake_secs > 0 { Some(p.latest_handshake_secs as i64) } else { None },
            transfer_rx: p.rx_bytes as i64,
            transfer_tx: p.tx_bytes as i64,
        }).collect())
    }

    pub fn remove_peer(interface: &str, public_key: &str) -> Result<()> {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let ifindex = rt.block_on(async {
            let (conn, handle, _) = new_connection().ok()?;
            tokio::spawn(conn);
            get_ifindex(&handle, interface).await
        }).ok_or_else(|| AppError::Internal("interface not found".into()))?;

        let peer = nl::WgPeerConfig {
            public_key: public_key.to_string(), preshared_key: None,
            persistent_keepalive: 0, allowed_ips: vec![],
            remove: true, replace_allowed_ips: false,
        };
        nl::set_device(ifindex, None, 0, false, &[peer])?;
        Ok(())
    }

    // rtnetlink helpers
    async fn get_ifindex(handle: &rtnetlink::Handle, name: &str) -> Option<u32> {
        use futures::TryStreamExt;
        let mut links = handle.link().get().match_name(name.to_string()).execute();
        while let Ok(Some(msg)) = links.try_next().await {
            return Some(msg.header.index);
        }
        None
    }

    async fn create_wg_iface(handle: &rtnetlink::Handle, name: &str) -> Result<()> {
        let mut msg = LinkMessage::default();
        msg.attributes.push(LinkAttribute::IfName(name.to_string()));
        msg.attributes.push(LinkAttribute::LinkInfo(vec![LinkInfo::Kind(InfoKind::WireGuard)]));
        handle.link().add(msg).execute().await
            .map_err(|e| AppError::Internal(format!("create interface '{name}': {e}")))?;
        info!("Created WireGuard interface '{name}'");
        Ok(())
    }

    async fn set_ip(handle: &rtnetlink::Handle, ifindex: u32, cidr: &str) -> Result<()> {
        use netlink_packet_route::address::AddressMessage;
        use netlink_packet_route::AddressFamily;
        let (ip_str, prefix) = cidr.split_once('/').unwrap_or((cidr, "24"));
        let ip = Ipv4Addr::from_str(ip_str).map_err(|_| AppError::BadRequest("Invalid IP".into()))?;
        let prefix_len: u8 = prefix.parse().unwrap_or(24);
        let mut msg = AddressMessage::default();
        msg.header.prefix_len = prefix_len;
        msg.header.index = ifindex;
        msg.header.family = AddressFamily::Inet;
        msg.attributes.push(AddressAttribute::Address(ip.octets().to_vec()));
        handle.address().add(msg).execute().await
            .map_err(|e| AppError::Internal(format!("set IP: {e}")))?;
        Ok(())
    }

    async fn bring_up(handle: &rtnetlink::Handle, ifindex: u32) -> Result<()> {
        use netlink_packet_route::link::LinkFlags;
        let mut msg = LinkMessage::default();
        msg.header.index = ifindex;
        msg.header.flags = LinkFlags::Up;
        msg.header.change_mask = LinkFlags::Up;
        handle.link().set(msg).execute().await
            .map_err(|e| AppError::Internal(format!("bring up: {e}")))?;
        Ok(())
    }
}
