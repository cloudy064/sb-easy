// Package config loads runtime configuration from environment variables,
// mirroring the env contract of the Rust backend.
package config

import (
	"os"
	"strings"
)

type Config struct {
	BindAddr   string
	DBPath     string
	JWTSecret  string
	AdminPassword string

	SingboxAPIURL    string
	SingboxAPISecret string

	// In-process sing-box management for the built-in self host.
	SingboxManaged    bool
	SelfConfigPath    string
	SelfInterval      int

	CORSOrigins   string
	ExternalHost  string
	AgentToken    string
	ConfigHashSeed string
	FrontendDir   string
}

func env(key, def string) string {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		return v
	}
	return def
}

// dbPathFromURL turns "sqlite:data/sb-easy.db?mode=rwc" into "data/sb-easy.db".
func dbPathFromURL(url string) string {
	s := strings.TrimPrefix(url, "sqlite:")
	if i := strings.IndexByte(s, '?'); i >= 0 {
		s = s[:i]
	}
	return s
}

func Load() Config {
	return Config{
		BindAddr:         env("BIND_ADDR", "0.0.0.0:51821"),
		DBPath:           dbPathFromURL(env("DATABASE_URL", "sqlite:data/sb-easy.db?mode=rwc")),
		JWTSecret:        env("JWT_SECRET", "dev-secret-change-me"),
		AdminPassword:    env("ADMIN_PASSWORD", "admin"),
		SingboxAPIURL:    env("SINGBOX_API_URL", "http://127.0.0.1:9090"),
		SingboxAPISecret: env("SINGBOX_API_SECRET", ""),
		SingboxManaged:   env("SINGBOX_MANAGED", "") == "true" || env("SINGBOX_MANAGED", "") == "1",
		SelfConfigPath:   env("SELF_SINGBOX_CONFIG_PATH", "data/sing-box.gen.json"),
		SelfInterval:     atoiDef(env("SELF_SINGBOX_INTERVAL", "10"), 10),
		CORSOrigins:      env("CORS_ORIGINS", ""),
		ExternalHost:     env("EXTERNAL_HOSTNAME", "127.0.0.1"),
		AgentToken:       env("AGENT_TOKEN", ""),
		ConfigHashSeed:   env("CONFIG_HASH_SEED", "sb-easy"),
		FrontendDir:      env("FRONTEND_DIR", "frontend/dist"),
	}
}

func atoiDef(s string, def int) int {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return def
		}
		n = n*10 + int(c-'0')
	}
	if n < 2 {
		return def
	}
	return n
}
