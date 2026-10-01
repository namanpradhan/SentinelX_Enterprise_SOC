# SentinelX Enterprise SOC v4.2.13 — Final Clean UI/Data Release

- Disabled automatic synthetic/demo data on first run.
- Removed visible demo credentials from the login page.
- Added live-environment onboarding when no telemetry exists.
- Added independent sidebar scrolling for full 100% browser zoom.
- Improved responsive grid, tables, toolbars and mobile breakpoints.
- Removed demo-only seed entry points and the synthetic UI preview asset.
- Session tokens remain in sessionStorage only.
- Preserved the stable v4.2 API and same-origin FastAPI architecture.

# Changelog

## 4.2.13 — Enterprise Security Expansion

### Added
- Vulnerability Scanner workspace and persisted findings.
- Nmap service/version assessment integration with optional authorized vulnerability scripts.
- Suricata and Snort 3 integration status plus recent alert ingestion surfaces.
- SentinelX defensive Suricata/Snort local rule templates.
- Metasploit defensive module-intelligence catalog and local-framework detection.
- Ollama AI provider/model detection and deterministic investigation fallback.
- Real-time host-visible network snapshot and richer neighbor data.
- Device-to-vulnerability linkage and per-device assessment action.
- Expanded deterministic detection catalog to 150+ rules.
- Dedicated SentinelX logo and refreshed application identity.
- Additional security middleware, request IDs, rate controls, trusted hosts and CSP headers.
- Deep acceptance test suite and security-stack setup guide.

### Corrected
- Demo seeding no longer creates duplicate devices from collector upserts.
- Incident demo data now exercises alert correlation.
- AI endpoint now returns a deterministic fallback whenever a local model service is unavailable.
- System status reports v4.2.13 consistently.
