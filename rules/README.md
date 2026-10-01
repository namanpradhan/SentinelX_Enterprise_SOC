# SentinelX Detection Rule Packs

SentinelX ships only original defensive example rules and integration templates. Third-party rule feeds remain the responsibility of the operator and should be obtained from their official sources and licenses.

## Suricata
- `rules/suricata/local.rules`
- Use the file as a local rule source after validating `HOME_NET` and `EXTERNAL_NET`.
- Suricata can operate in IDS or inline IPS mode depending on the deployment. Inline mode must be tested carefully before production enforcement.

## Snort 3
- `rules/snort/local.rules`
- Include the file through the Snort 3 `ips` rule configuration.

## Safety
The example rules detect exposure patterns; they do not deliver exploits, payloads, brute force traffic or denial-of-service traffic.
