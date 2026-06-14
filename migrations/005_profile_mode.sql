-- =============================================
-- sb-easy migration 005
-- Profile render mode:
--   'managed' (default) — template is config minus outbounds; sb-easy injects
--                         the host's assigned proxies + Auto/Proxy selectors.
--   'full'              — template is a COMPLETE sing-box config, run verbatim
--                         (only experimental.clash_api is added if missing).
--                         For importing hand-tuned configs as one editable blob.
-- =============================================

ALTER TABLE config_profiles ADD COLUMN mode TEXT NOT NULL DEFAULT 'managed';
