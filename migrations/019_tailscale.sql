-- Independent per-host Tailscale enrollment and routing settings.
-- Existing hosts remain on their existing network until explicitly enabled.
ALTER TABLE hosts ADD COLUMN tailscale TEXT NOT NULL DEFAULT '{}';
