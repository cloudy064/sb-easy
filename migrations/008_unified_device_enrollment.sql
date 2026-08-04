-- Device enrollment is shared by Android and native agents.  Keep the profile
-- id stable for existing assignments while removing the platform-specific name.
UPDATE config_profiles
SET name = 'Managed Device', updated_at = datetime('now')
WHERE id = 'android-client' AND name = 'Android Client';
