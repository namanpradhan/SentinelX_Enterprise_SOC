# Security Guidance

SentinelX is a defensive SIEM/SOC project. It is **not** a claim of absolute, unhackable or production-certified security.

## Local development baseline

- Bind API and frontend to `127.0.0.1` for local work.
- Replace or rotate all bootstrap credentials before sharing or deploying the repository.
- Never commit `.env`, database files, API keys, certificates or virtual environments.
- Restrict network discovery and vulnerability assessment to systems and networks you are authorized to assess.
- Review the 150+ deterministic rules for expected false positives before production use.

## Hardening in v4.2.8

- Trusted Host validation
- Strict local CORS allowlist
- Request-size limit
- Lightweight API rate guard
- Request IDs for operational tracing
- Content Security Policy and cross-origin headers
- Session token hashing at rest
- Idle and absolute session expiry
- Login failure throttling
- RBAC and permission checks
- Audit trail
- Protected collector endpoint with optional agent key
- AI is advisory; deterministic detections remain authoritative

## Production hardening still required

For a production deployment, add:

- HTTPS/TLS behind a hardened reverse proxy or gateway;
- enterprise identity integration and phishing-resistant MFA;
- centralized secret management;
- production database and backup strategy;
- tamper-resistant centralized logging;
- dependency and operating-system patch management;
- network segmentation and firewall policy;
- WAF/rate limiting at the edge;
- security monitoring of the SentinelX infrastructure itself;
- formal vulnerability assessment and authorized penetration testing;
- incident-response, disaster-recovery and restore procedures.

## Network discovery boundaries

The local discovery implementation uses host-visible network information and active probes. It cannot bypass Wi-Fi client isolation, VLAN boundaries, host firewalls, sleeping clients or access-control policy. Full enterprise asset discovery should combine authoritative network controller/AP telemetry with endpoint agents.

## Vulnerability assessment

Nmap and NSE are powerful assessment technologies. SentinelX limits the web workflow to private/local targets and requires explicit authorization confirmation for deep vulnerability-script execution. SentinelX records evidence and recommendations; it does not execute exploits or deliver payloads.

## IDS/IPS integrations

Suricata and Snort 3 are external sensors. Test inline IPS rules in a controlled segment before enforcing them in production. Validate third-party/community rule feed licenses and update procedures separately.

## AI usage

The AI analyst is advisory. It must not be treated as the authoritative detection engine, autonomous attribution mechanism, or sole basis for containment. The deterministic rule engine, correlation logic and security telemetry remain authoritative.
