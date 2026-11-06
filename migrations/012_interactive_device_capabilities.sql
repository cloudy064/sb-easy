-- Rendering is capability-driven rather than keyed to a platform label. Keep
-- already-enrolled Android clients compatible by materializing the capabilities
-- that released clients implied before these fields were added to enrollment.
UPDATE hosts
SET capabilities = json_set(capabilities, '$.interactive_client', json('true')),
    updated_at = datetime('now')
WHERE json_valid(capabilities)
  AND json_extract(capabilities, '$.platform') = 'android'
  AND json_type(capabilities, '$.interactive_client') IS NULL;

UPDATE hosts
SET capabilities = json_set(capabilities, '$.supports_proxy_selection', json('true')),
    updated_at = datetime('now')
WHERE json_valid(capabilities)
  AND json_extract(capabilities, '$.platform') = 'android'
  AND json_type(capabilities, '$.supports_proxy_selection') IS NULL;

UPDATE hosts
SET capabilities = json_set(capabilities, '$.supports_local_route_stats', json('true')),
    updated_at = datetime('now')
WHERE json_valid(capabilities)
  AND json_extract(capabilities, '$.platform') = 'android'
  AND json_type(capabilities, '$.supports_local_route_stats') IS NULL;

UPDATE hosts
SET capabilities = json_set(capabilities, '$.supports_diagnostic_upload', json('true')),
    updated_at = datetime('now')
WHERE json_valid(capabilities)
  AND json_extract(capabilities, '$.platform') = 'android'
  AND json_type(capabilities, '$.supports_diagnostic_upload') IS NULL;

UPDATE hosts
SET capabilities = json_set(capabilities, '$.embedded_wireguard', json('true')),
    updated_at = datetime('now')
WHERE json_valid(capabilities)
  AND json_extract(capabilities, '$.platform') = 'android'
  AND json_type(capabilities, '$.embedded_wireguard') IS NULL;
