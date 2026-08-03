-- Use Android's current physical network DNS only to bootstrap proxy endpoint
-- names. Application DNS then travels through the selected proxy as DoH, which
-- avoids carrier blocking of public UDP/53 without giving up secure DNS.
UPDATE config_profiles
SET template = json_set(
        template,
        '$.dns', json('{"servers":[{"type":"local","tag":"local-dns"},{"type":"https","tag":"secure-dns","server":"1.1.1.1","server_port":443,"path":"/dns-query","tls":{"enabled":true,"server_name":"cloudflare-dns.com"},"detour":"Proxy"}],"rules":[{"domain_suffix":[".lan",".local"],"action":"route","server":"local-dns"}],"final":"secure-dns","strategy":"prefer_ipv4","independent_cache":true}'),
        '$.route.default_domain_resolver', json('{"server":"local-dns","strategy":"prefer_ipv4"}')
    ),
    updated_at = datetime('now')
WHERE id = 'android-client';
