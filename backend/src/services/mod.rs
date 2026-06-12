pub mod proxy_config;
pub mod subscription;
pub mod uri_parser;
pub mod wireguard;

// Linux-only: netlink WireGuard kernel interface
#[cfg(target_os = "linux")]
pub mod wireguard_nl;
