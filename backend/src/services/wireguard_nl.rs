//! Pure-Rust WireGuard kernel interface via netlink (Linux only).
//! No external `wg` / `wg-quick` / `ip` CLI tools required.
#![cfg(target_os = "linux")]

use std::net::Ipv4Addr;

use base64::Engine;
use neli::consts::genl::*;
use neli::consts::nl::*;
use neli::consts::socket::*;
use neli::genl::Genlmsghdr;
use neli::nl::{NlPayload, Nlmsghdr};
use neli::socket::NlSocketHandle;
use neli::types::{GenlBuffer, NlBuffer};
use rand::rngs::OsRng;
use tracing::{info, warn};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::error::{AppError, Result};

// ── WG netlink constants ────────────────────────────────────

const WG_GENL_NAME: &str = "wireguard";
const WG_CMD_GET_DEVICE: u8 = 0;
const WG_CMD_SET_DEVICE: u8 = 1;

const WGDEVICE_A_IFINDEX: u16 = 0;
const WGDEVICE_A_IFNAME: u16 = 1;
const WGDEVICE_A_PRIVATE_KEY: u16 = 2;
const WGDEVICE_A_PUBLIC_KEY: u16 = 3;
const WGDEVICE_A_FLAGS: u16 = 4;
const WGDEVICE_A_LISTEN_PORT: u16 = 5;
const WGDEVICE_A_PEERS: u16 = 7;
const WGDEVICE_F_REPLACE_PEERS: u32 = 1;

const WGPEER_A_PUBLIC_KEY: u16 = 0;
const WGPEER_A_PRESHARED_KEY: u16 = 1;
const WGPEER_A_FLAGS: u16 = 2;
const WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL: u16 = 4;
const WGPEER_A_LAST_HANDSHAKE_TIME: u16 = 5;
const WGPEER_A_RX_BYTES: u16 = 6;
const WGPEER_A_TX_BYTES: u16 = 7;
const WGPEER_A_ALLOWEDIPS: u16 = 8;
const WGPEER_F_REMOVE_ME: u32 = 1;
const WGPEER_F_REPLACE_ALLOWEDIPS: u32 = 1 << 1;

const WGALLOWEDIP_A_FAMILY: u16 = 0;
const WGALLOWEDIP_A_IPADDR: u16 = 1;
const WGALLOWEDIP_A_CIDR_MASK: u16 = 2;
const AF_INET: u16 = 2;

// ── Public types ────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct WgPeerInfo {
    pub public_key: String,
    pub preshared_key: Option<String>,
    pub endpoint: Option<String>,
    pub latest_handshake_secs: u64,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub persistent_keepalive: u16,
    pub allowed_ips: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct WgDeviceInfo {
    pub ifindex: u32,
    pub ifname: String,
    pub public_key: String,
    pub listen_port: u16,
    pub peers: Vec<WgPeerInfo>,
}

#[derive(Debug, Clone)]
pub struct WgPeerConfig {
    pub public_key: String,
    pub preshared_key: Option<String>,
    pub persistent_keepalive: u16,
    pub allowed_ips: Vec<String>,
    pub remove: bool,
    pub replace_allowed_ips: bool,
}

// ── Key generation (x25519 pure Rust, works everywhere) ─────

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

pub fn generate_keypair() -> (String, String) {
    let private = generate_private_key();
    let public = public_key_from_private(&private).unwrap_or_default();
    (private, public)
}

// ── Netlink communication ───────────────────────────────────

fn connect_wg_socket() -> Result<(NlSocketHandle, u16)> {
    let sock = NlSocketHandle::connect(NlFamily::Generic, None, &[])
        .map_err(|e| AppError::Internal(format!("genetlink socket: {e}")))?;
    let family_id = resolve_family(&sock, WG_GENL_NAME)?;
    Ok((sock, family_id))
}

fn resolve_family(sock: &NlSocketHandle, name: &str) -> Result<u16> {
    let mut attrs = GenlBuffer::new();
    attrs.push((CTRL_ATTR_FAMILY_NAME, name.as_bytes().to_vec()));

    let genl_hdr = Genlmsghdr::new(CTRL_CMD_GETFAMILY, 1, attrs);
    let nl_hdr = Nlmsghdr::new(None, GENL_ID_CTRL, NlmFFlags::new(&[NlmF::Request]), None, None, NlPayload::Payload(genl_hdr));

    let mut buf: Vec<u8> = Vec::new();
    sock.send(&nl_hdr).map_err(|e| AppError::Internal(format!("genetlink send: {e}")))?;
    let received = sock.recv::<Nlmsghdr<u16, Genlmsghdr<u16, GenlBuffer<u16, Vec<u8>>>>>(&mut buf)
        .map_err(|e| AppError::Internal(format!("genetlink recv: {e}")))?;

    let (_hdr, genl_resp) = received.destructure();
    let resp_attrs = genl_resp.get_attr_handle();
    let family_id_bytes = resp_attrs.get_attribute(CTRL_ATTR_FAMILY_ID)
        .map_err(|_| AppError::Internal(format!("genetlink family '{name}' not found")))?;
    let payload = family_id_bytes.payload();
    let family_id = u16::from_ne_bytes([payload[0], payload[1]]);

    info!("Resolved genetlink family '{name}' → id={family_id}");
    Ok(family_id)
}

// ── get_device ──────────────────────────────────────────────

pub fn get_device(ifindex: u32) -> Result<WgDeviceInfo> {
    let (sock, family_id) = connect_wg_socket()?;

    let mut attrs = GenlBuffer::new();
    attrs.push((WGDEVICE_A_IFINDEX, ifindex.to_ne_bytes().to_vec()));

    let genl_hdr = Genlmsghdr::new(WG_CMD_GET_DEVICE, 1, attrs);
    let nl_hdr = Nlmsghdr::new(None, family_id, NlmFFlags::new(&[NlmF::Request, NlmF::Dump]), None, None, NlPayload::Payload(genl_hdr));

    let mut buf: Vec<u8> = Vec::new();
    sock.send(&nl_hdr).map_err(|e| AppError::Internal(format!("wg get_device send: {e}")))?;
    let received = sock.recv::<Nlmsghdr<u16, Genlmsghdr<u16, GenlBuffer<u16, Vec<u8>>>>>(&mut buf)
        .map_err(|e| AppError::Internal(format!("wg get_device recv: {e}")))?;

    parse_device_response(&received)
}

fn parse_device_response(msg: &Nlmsghdr<u16, Genlmsghdr<u16, GenlBuffer<u16, Vec<u8>>>>) -> Result<WgDeviceInfo> {
    let (_nl_hdr, genl_hdr) = msg.destructure();
    let attrs = genl_hdr.get_attr_handle();

    let ifname = attrs.get_attribute(WGDEVICE_A_IFNAME).ok()
        .map(|a| String::from_utf8_lossy(a.payload()).trim_end_matches('\0').to_string())
        .unwrap_or_default();

    let ifindex = attrs.get_attribute(WGDEVICE_A_IFINDEX).ok()
        .and_then(|a| {
            let p = a.payload();
            if p.len() >= 4 { Some(u32::from_ne_bytes([p[0], p[1], p[2], p[3]])) }
            else { None }
        }).unwrap_or(0);

    let public_key = attrs.get_attribute(WGDEVICE_A_PUBLIC_KEY).ok()
        .map(|a| base64::engine::general_purpose::STANDARD.encode(a.payload()))
        .unwrap_or_default();

    let listen_port = attrs.get_attribute(WGDEVICE_A_LISTEN_PORT).ok()
        .and_then(|a| {
            let p = a.payload();
            if p.len() >= 2 { Some(u16::from_ne_bytes([p[0], p[1]])) }
            else { None }
        }).unwrap_or(0);

    let peers = attrs.get_attribute(WGDEVICE_A_PEERS).ok()
        .map(|a| parse_peers_raw(a.payload()))
        .unwrap_or_else(|| Ok(Vec::new()))?;

    Ok(WgDeviceInfo { ifindex, ifname, public_key, listen_port, peers })
}

// ── set_device ──────────────────────────────────────────────

pub fn set_device(ifindex: u32, private_key: Option<&str>, listen_port: u16, replace_peers: bool, peers: &[WgPeerConfig]) -> Result<()> {
    let (sock, family_id) = connect_wg_socket()?;

    let mut attrs = GenlBuffer::new();
    attrs.push((WGDEVICE_A_IFINDEX, ifindex.to_ne_bytes().to_vec()));

    if let Some(key) = private_key {
        let key_bytes = base64::engine::general_purpose::STANDARD
            .decode(key)
            .map_err(|e| AppError::BadRequest(format!("Invalid key: {e}")))?;
        attrs.push((WGDEVICE_A_PRIVATE_KEY, key_bytes));
    }

    attrs.push((WGDEVICE_A_LISTEN_PORT, listen_port.to_ne_bytes().to_vec()));

    let mut flags = 0u32;
    if replace_peers { flags |= WGDEVICE_F_REPLACE_PEERS; }
    attrs.push((WGDEVICE_A_FLAGS, flags.to_ne_bytes().to_vec()));

    if !peers.is_empty() {
        attrs.push((WGDEVICE_A_PEERS, encode_peers_raw(peers)?));
    }

    let genl_hdr = Genlmsghdr::new(WG_CMD_SET_DEVICE, 1, attrs);
    let nl_hdr = Nlmsghdr::new(None, family_id, NlmFFlags::new(&[NlmF::Request]), None, None, NlPayload::Payload(genl_hdr));

    sock.send(&nl_hdr).map_err(|e| AppError::Internal(format!("wg set_device send: {e}")))?;
    Ok(())
}

// ── Low-level peer encoding/decoding ────────────────────────

fn encode_peers_raw(peers: &[WgPeerConfig]) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    for peer in peers {
        let peer_bytes = encode_one_peer(peer)?;
        let total_len = (4 + peer_bytes.len()) as u16;
        buf.extend_from_slice(&total_len.to_ne_bytes());
        buf.extend_from_slice(&0u16.to_ne_bytes());
        buf.extend_from_slice(&peer_bytes);
        while buf.len() % 4 != 0 { buf.push(0); }
    }
    Ok(buf)
}

fn encode_one_peer(peer: &WgPeerConfig) -> Result<Vec<u8>> {
    let mut buf = Vec::new();

    let pk = base64::engine::general_purpose::STANDARD
        .decode(&peer.public_key)
        .map_err(|e| AppError::BadRequest(format!("Invalid peer public key: {e}")))?;
    push_nla(&mut buf, WGPEER_A_PUBLIC_KEY, &pk);

    if let Some(ref psk) = peer.preshared_key {
        let psk_bytes = base64::engine::general_purpose::STANDARD
            .decode(psk)
            .map_err(|e| AppError::BadRequest(format!("Invalid PSK: {e}")))?;
        push_nla(&mut buf, WGPEER_A_PRESHARED_KEY, &psk_bytes);
    }

    if peer.persistent_keepalive > 0 {
        push_nla(&mut buf, WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL, &peer.persistent_keepalive.to_ne_bytes());
    }

    let mut flags = 0u32;
    if peer.remove { flags |= WGPEER_F_REMOVE_ME; }
    if peer.replace_allowed_ips { flags |= WGPEER_F_REPLACE_ALLOWEDIPS; }
    if flags != 0 {
        push_nla(&mut buf, WGPEER_A_FLAGS, &flags.to_ne_bytes());
    }

    if !peer.allowed_ips.is_empty() {
        let ips_buf = encode_allowed_ips(&peer.allowed_ips);
        push_nla(&mut buf, WGPEER_A_ALLOWEDIPS, &ips_buf);
    }

    Ok(buf)
}

fn encode_allowed_ips(ips: &[String]) -> Vec<u8> {
    let mut buf = Vec::new();
    for ip_str in ips {
        if let Ok(parsed) = parse_cidr(ip_str) {
            let mut ip_buf = Vec::new();
            push_nla(&mut ip_buf, WGALLOWEDIP_A_FAMILY, &AF_INET.to_ne_bytes());
            push_nla(&mut ip_buf, WGALLOWEDIP_A_IPADDR, &parsed.0.octets());
            push_nla(&mut ip_buf, WGALLOWEDIP_A_CIDR_MASK, &[parsed.1]);

            let total = (4 + ip_buf.len()) as u16;
            buf.extend_from_slice(&total.to_ne_bytes());
            buf.extend_from_slice(&0u16.to_ne_bytes());
            buf.extend_from_slice(&ip_buf);
            while buf.len() % 4 != 0 { buf.push(0); }
        }
    }
    buf
}

fn parse_cidr(cidr: &str) -> Result<(Ipv4Addr, u8)> {
    let parts: Vec<&str> = cidr.split('/').collect();
    let ip: Ipv4Addr = parts[0].parse().map_err(|_| AppError::BadRequest("Invalid IP".into()))?;
    let mask: u8 = if parts.len() > 1 { parts[1].parse().unwrap_or(32) } else { 32 };
    Ok((ip, mask))
}

fn parse_peers_raw(data: &[u8]) -> Result<Vec<WgPeerInfo>> {
    let mut peers = Vec::new();
    let mut pos = 0;
    while pos + 4 <= data.len() {
        let len = u16::from_ne_bytes([data[pos], data[pos + 1]]) as usize;
        if len < 4 || pos + len > data.len() { break; }
        let payload = &data[pos + 4..pos + len];
        if let Ok(peer) = parse_one_peer(payload) {
            peers.push(peer);
        }
        pos += len;
        while pos % 4 != 0 && pos < data.len() { pos += 1; }
    }
    Ok(peers)
}

fn parse_one_peer(data: &[u8]) -> Result<WgPeerInfo> {
    let mut public_key = String::new();
    let mut preshared_key = None;
    let mut latest_handshake_secs = 0u64;
    let mut rx_bytes = 0u64;
    let mut tx_bytes = 0u64;
    let mut persistent_keepalive = 0u16;
    let mut allowed_ips = Vec::new();

    let mut pos = 0;
    while pos + 4 <= data.len() {
        let len = u16::from_ne_bytes([data[pos], data[pos + 1]]) as usize;
        let attr_type = u16::from_ne_bytes([data[pos + 2], data[pos + 3]]);
        if len < 4 || pos + len > data.len() { break; }
        let payload = &data[pos + 4..pos + len];

        match attr_type {
            WGPEER_A_PUBLIC_KEY => { public_key = base64::engine::general_purpose::STANDARD.encode(payload); }
            WGPEER_A_PRESHARED_KEY => { preshared_key = Some(base64::engine::general_purpose::STANDARD.encode(payload)); }
            WGPEER_A_LAST_HANDSHAKE_TIME => {
                if payload.len() >= 8 {
                    let nsec = u64::from_ne_bytes(payload[..8].try_into().unwrap());
                    latest_handshake_secs = nsec / 1_000_000_000;
                }
            }
            WGPEER_A_RX_BYTES => { if payload.len() >= 8 { rx_bytes = u64::from_ne_bytes(payload[..8].try_into().unwrap()); } }
            WGPEER_A_TX_BYTES => { if payload.len() >= 8 { tx_bytes = u64::from_ne_bytes(payload[..8].try_into().unwrap()); } }
            WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL => {
                if payload.len() >= 2 { persistent_keepalive = u16::from_ne_bytes([payload[0], payload[1]]); }
            }
            WGPEER_A_ALLOWEDIPS => { allowed_ips = parse_allowed_ips(payload); }
            _ => {}
        }
        pos += len;
        while pos % 4 != 0 && pos < data.len() { pos += 1; }
    }

    Ok(WgPeerInfo { public_key, preshared_key, endpoint: None, latest_handshake_secs, rx_bytes, tx_bytes, persistent_keepalive, allowed_ips })
}

fn parse_allowed_ips(data: &[u8]) -> Vec<String> {
    let mut ips = Vec::new();
    let mut pos = 0;
    while pos + 4 <= data.len() {
        let len = u16::from_ne_bytes([data[pos], data[pos + 1]]) as usize;
        if len < 4 || pos + len > data.len() { break; }
        let payload = &data[pos + 4..pos + len];

        let mut ip: Option<Ipv4Addr> = None;
        let mut mask: u8 = 32;
        let mut ipos = 0;
        while ipos + 4 <= payload.len() {
            let ilen = u16::from_ne_bytes([payload[ipos], payload[ipos + 1]]) as usize;
            let itype = u16::from_ne_bytes([payload[ipos + 2], payload[ipos + 3]]);
            if ilen < 4 || ipos + ilen > payload.len() { break; }
            let ipayload = &payload[ipos + 4..ipos + ilen];

            match itype {
                WGALLOWEDIP_A_IPADDR => {
                    if ipayload.len() >= 4 { ip = Some(Ipv4Addr::new(ipayload[0], ipayload[1], ipayload[2], ipayload[3])); }
                }
                WGALLOWEDIP_A_CIDR_MASK => { if !ipayload.is_empty() { mask = ipayload[0]; } }
                _ => {}
            }
            ipos += ilen;
            while ipos % 4 != 0 && ipos < payload.len() { ipos += 1; }
        }
        if let Some(addr) = ip { ips.push(format!("{addr}/{mask}")); }
        pos += len;
        while pos % 4 != 0 && pos < data.len() { pos += 1; }
    }
    ips
}

fn push_nla(buf: &mut Vec<u8>, attr_type: u16, payload: &[u8]) {
    let total_len = (4 + payload.len()) as u16;
    buf.extend_from_slice(&total_len.to_ne_bytes());
    buf.extend_from_slice(&attr_type.to_ne_bytes());
    buf.extend_from_slice(payload);
    while buf.len() % 4 != 0 { buf.push(0); }
}
