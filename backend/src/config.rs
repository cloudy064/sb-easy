//! Application configuration from environment variables.
use anyhow::Context;
use std::env;

#[derive(Clone, Debug)]
pub struct Config {
    /// Bind address for HTTP server
    pub bind_addr: String,

    /// SQLite database URL
    pub database_url: String,

    /// JWT signing secret
    pub jwt_secret: String,

    /// Default admin password (only used for initial seed)
    pub admin_password: String,

    /// Shared token the agent must present to fetch config (empty = endpoint disabled)
    pub agent_token: String,

    /// Allowed CORS origins (comma-separated). Empty/"*" = permissive.
    pub cors_origins: String,

    // WireGuard settings
    pub wg_enabled: bool,
    pub wg_interface: String,
    pub wg_port: u16,
    pub wg_address: String,
    pub wg_dns: String,
    pub wg_mtu: u32,

    // Sing-box settings
    pub singbox_api_url: String,
    pub singbox_api_secret: String,

    // Server settings
    pub external_hostname: String,

    /// Config hash seed for Agent ETag
    pub config_hash_seed: String,

    /// In-process management of the built-in `self` host's sing-box.
    /// Empty path = disabled (self config is renderable but not auto-applied).
    pub self_singbox_config_path: String,
    pub self_reload_cmd: String,
    pub self_singbox_interval: u64,

    /// When true, sb-easy supervises sing-box itself as a child process
    /// (spawn / restart-on-change / respawn-on-crash) — no external sing-box
    /// service to run. Overrides the external-reload self-agent mode.
    pub singbox_managed: bool,
    /// Path to the sing-box binary to supervise.
    pub singbox_bin: String,
}

impl Config {
    pub fn from_env() -> anyhow::Result<Self> {
        // Load .env file if present
        let _ = dotenvy::dotenv();

        Ok(Self {
            bind_addr: env::var("BIND_ADDR").unwrap_or_else(|_| "0.0.0.0:51821".into()),
            database_url: env::var("DATABASE_URL")
                .unwrap_or_else(|_| "sqlite:data/sb-easy.db?mode=rwc".into()),
            jwt_secret: env::var("JWT_SECRET")
                .context("JWT_SECRET must be set")?,
            admin_password: env::var("ADMIN_PASSWORD")
                .unwrap_or_else(|_| "admin".into()),
            agent_token: env::var("AGENT_TOKEN").unwrap_or_default(),
            cors_origins: env::var("CORS_ORIGINS").unwrap_or_default(),

            wg_enabled: env::var("WG_ENABLED").unwrap_or_else(|_| "true".into()).parse().unwrap_or(true),
            wg_interface: env::var("WG_INTERFACE").unwrap_or_else(|_| "wg0".into()),
            wg_port: env::var("WG_PORT").unwrap_or_else(|_| "51820".into()).parse()?,
            wg_address: env::var("WG_ADDRESS").unwrap_or_else(|_| "10.59.32.1/24".into()),
            wg_dns: env::var("WG_DNS").unwrap_or_else(|_| "10.59.32.1".into()),
            wg_mtu: env::var("WG_MTU").unwrap_or_else(|_| "1420".into()).parse()?,

            singbox_api_url: env::var("SINGBOX_API_URL")
                .unwrap_or_else(|_| "http://127.0.0.1:9090".into()),
            singbox_api_secret: env::var("SINGBOX_API_SECRET").unwrap_or_default(),

            external_hostname: env::var("EXTERNAL_HOSTNAME")
                .unwrap_or_else(|_| "127.0.0.1".into()),

            config_hash_seed: env::var("CONFIG_HASH_SEED").unwrap_or_else(|_| uuid::Uuid::new_v4().to_string()),

            self_singbox_config_path: env::var("SELF_SINGBOX_CONFIG_PATH").unwrap_or_default(),
            self_reload_cmd: env::var("SELF_RELOAD_CMD")
                .unwrap_or_else(|_| "sudo systemctl reload sing-box".into()),
            self_singbox_interval: env::var("SELF_SINGBOX_INTERVAL")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(10)
                .max(2),

            singbox_managed: env::var("SINGBOX_MANAGED")
                .map(|v| v == "true" || v == "1")
                .unwrap_or(false),
            singbox_bin: env::var("SINGBOX_BIN").unwrap_or_else(|_| "sing-box".into()),
        })
    }
}
