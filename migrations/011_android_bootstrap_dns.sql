-- The custom Android client does not provide sing-box's optional platform
-- LocalDNSTransport, so a local server falls back to an unavailable loopback
-- resolver. Bootstrap proxy endpoint names through a domestic direct DoH
-- endpoint instead; regular application DNS remains proxied via secure-dns.
UPDATE config_profiles
SET template = json_set(
        template,
        '$.dns.servers[0]', json('{"type":"https","tag":"bootstrap-dns","server":"223.5.5.5","server_port":443,"path":"/dns-query","tls":{"enabled":true,"server_name":"dns.alidns.com"}}'),
        '$.dns.rules', json('[{"domain_suffix":[".lan",".local"],"action":"route","server":"bootstrap-dns"}]'),
        '$.route.default_domain_resolver', json('{"server":"bootstrap-dns","strategy":"prefer_ipv4"}')
    ),
    updated_at = datetime('now')
WHERE id = 'android-client';
