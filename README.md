# SentinelX Enterprise SOC v4.2.13

**Detect • Analyze • Respond • Protect**

SentinelX is a Windows-friendly defensive Security Information and Event Management (SIEM) and Security Operations Center (SOC) platform for authorized security monitoring, network visibility, vulnerability assessment, detection engineering, incident handling and analyst assistance.

Developed & Maintained by **Naman Pradhan** • Cyber Security Engineer • https://www.namanpradhan.me

## What v4.2.13 adds to the proven v4.2 architecture

- Stronger network discovery with Windows neighbor state, ARP refresh, ICMP probing, optional Nmap ARP discovery, hostname/NetBIOS enrichment and TCP service probing.
- Live network visibility view that distinguishes host-visible peers from authoritative controller/AP inventory.
- Device Fleet integration with vulnerability counts and per-device security assessment.
- Authorized internal vulnerability assessment using Nmap service/version detection plus SentinelX exposure heuristics. Optional Nmap vulnerability scripts require explicit authorization and remain evidence-only; SentinelX does not exploit targets.
- New Vulnerability Scanner workspace with findings, severity/risk, evidence, remediation and status lifecycle.
- New IDS / IPS workspace with Suricata and Snort 3 health/alert ingestion surfaces.
- Defensive local rule templates for Suricata and Snort under `rules/`.
- Metasploit module intelligence catalog and local-framework detection. Exploit execution, payload generation and destructive actions are intentionally not exposed in the UI.
- AI Analyst provider/model status with Ollama support and deterministic analyst fallback.
- Additional hardening: request limits, per-route rate guard, trusted-host validation, CSP/security headers, protected collector endpoints and request IDs.
- - SentinelX brand identity with a dedicated shield/X logo, favicon, refined responsive header/sidebar/footer and professional security language.

## SOC workspaces

1. **Command Center** — posture score, KPI cards, 24-hour threat activity, severity distribution, top detections, network snapshot and live activity.
2. **Device Fleet** — asset inventory, source/platform/status/risk filters, device details and vulnerability assessment.
3. **Network Discovery** — host network, Wi-Fi context, visible neighbors, deep local discovery and auto-discovery.
4. **Threat Queue** — alert lifecycle, search, severity/status/MITRE/risk filters and sorting.
5. **Incident Response** — correlated case lifecycle and investigation controls.
6. **Event Stream** — normalized event telemetry and filtering.
7. **ATT&CK Coverage** — observed techniques and enabled detection catalog coverage.
8. **Detection Engineering** — 150+ deterministic rules, lifecycle controls and a rule test bench.
9. **AI Analyst** — local model status, model inventory, investigation assistance and deterministic fallback.
10. **Vulnerability Scanner** — asset/service discovery and exposure findings.
11. **IDS / IPS** — Suricata and Snort 3 integration status and recent sensor alerts.
12. **Exploit Intelligence** — defensive Metasploit module catalog and framework status.
13. **Identity & Access** — Admin/Employee/User RBAC, sessions, audit and password security.
14. **Reports & Export** — executive view and CSV exports.
15. **Security Center** — runtime posture, network context, controls and diagnostics.

## Security architecture

```text
Windows / macOS / Linux / Mobile / Network / Cloud telemetry
                         │
                         ▼
                 SentinelX Collectors
                         │
                         ▼
                   Normalization
                         │
                         ▼
                Deterministic Rules
                         │
             ┌───────────┴───────────┐
             ▼                       ▼
      Correlation Engine        Risk Scoring
             │                       │
             └───────────┬───────────┘
                         ▼
                MITRE ATT&CK Mapping
                         │
        ┌────────────────┼─────────────────┐
        ▼                ▼                 ▼
 Vulnerability      IDS / IPS         AI Analyst
 Assessment         Integration      Assistance
        │                │                 │
        └────────────────┼─────────────────┘
                         ▼
                 SOC Command Center
```

## Network visibility boundary

SentinelX intentionally reports **host-visible peers** separately from controller-authoritative inventory. A Windows client cannot reliably enumerate every Wi-Fi client when AP client isolation, VLAN segmentation, host firewalls, sleep state or controller policy hides those peers. For enterprise-wide inventory, integrate the wireless controller/AP and endpoint agents.

## Vulnerability assessment

The default assessment path uses Nmap service/version detection and SentinelX exposure heuristics. A deeper Nmap vulnerability-script run is available only for a private/local target with explicit authorization confirmation. Findings are persisted as evidence and remediation recommendations; SentinelX does not deliver exploits or payloads.

## IDS / IPS integration

SentinelX can report locally installed **Suricata** and **Snort 3** sensors and consume configured alert feeds. It includes original defensive sample rules in:

- `rules/suricata/local.rules`
- `rules/snort/local.rules`

Third-party/commercial/community rule feeds are not redistributed by this repository.

## AI integration

Ollama is optional. SentinelX checks the local Ollama API, lists available models, and uses a configured model for investigation assistance when available. Otherwise, a deterministic evidence-based fallback is returned.

Configure through `.env` / environment variables:

```text
SENTINELX_OLLAMA_URL=http://127.0.0.1:11434
SENTINELX_OLLAMA_MODEL=llama3.2
SENTINELX_AI_MODELS=llama3.2,qwen2.5:7b,gemma3:4b
```

## Security controls

- Role-based access control
- Opaque server-side bearer sessions with hashed tokens
- 8-hour absolute session lifetime by default
- 30-minute idle timeout by default
- Login failure throttling
- PBKDF2-SHA256 password hashing
- Logout / logout-all / session revocation
- Request ID tracing
- Trusted-host validation
- CORS allowlist for local development
- Content Security Policy and cross-origin hardening headers
- Request-size limit
- Lightweight API rate guard
- Authenticated collector endpoints
- Audit trail
- Deterministic detection authority; AI is advisory only

## Start on Windows 11

### Recommended

Double-click:

```text
START_SENTINELX.bat
```

The launcher:

1. creates `venv` if required;
2. installs the root `requirements.txt`;
3. starts FastAPI on `127.0.0.1:8000`;
4. waits for `/health`;
5. initializes the application schema and access controls; no synthetic devices, events or alerts are created;
6. serves the web UI from FastAPI on `127.0.0.1:8000`;
7. opens the browser.

### Manual

```powershell
cd "C:\Path\To\SentinelX_Enterprise_SOC_v4_2_8_FINAL"
python -m venv venv
.\venv\Scripts\Activate.ps1
python -m pip install -r .\requirements.txt
cd .\backend
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```

No second frontend terminal is required.

Open `http://127.0.0.1:8000`.

## Local access

The clean release does not display credentials in the UI and does not seed synthetic security data. The local administrator accounts are intended for development setup; change their credentials before external deployment.

## Clean-data policy

The clean release reflects only telemetry, devices, alerts and findings actually supplied by SentinelX collectors, agents, discovery, IDS/IPS integrations and authorized assessment workflows.

## Validation

```powershell
python tests/smoke_test.py
python tests/full_acceptance.py
node --check frontend/app.js
```

Optional browser validation is provided in `tests/browser_smoke.py`.

## Third-party references

- Nmap: https://nmap.org/
- Suricata: https://suricata.io/ and https://docs.suricata.io/
- Snort 3: https://snort.org/ and https://docs.snort.org/
- Metasploit Framework: https://docs.rapid7.com/metasploit/
- Ollama: https://ollama.com/
- MITRE ATT&CK: https://attack.mitre.org/

## License

MIT. See `LICENSE`.

## Responsible use

Use SentinelX only on systems and networks you own or are explicitly authorized to assess. IDS/IPS enforcement, vulnerability scanning and third-party security tools should be deployed under an approved change/assessment process.


## v4.2.13 local architecture
The web UI is served directly by FastAPI from the same origin as the API. This removes the second local web server and eliminates a common source of frontend/API connection drift. Start `START_SENTINELX.bat` and open `http://127.0.0.1:8000/`.

## Windows SQLAlchemy compatibility
SentinelX sets `DISABLE_SQLALCHEMY_CEXT_RUNTIME=1` for local Windows launches. This keeps SQLAlchemy on its supported Python implementation when Windows application-control policies block optional native extension DLLs.

## Windows first-run
Use `START_SENTINELX.bat`. This release serves the UI and API from the same FastAPI process on `http://127.0.0.1:8000/`. Do not start a separate static HTTP server. The dependency set stays on the SQLAlchemy 2.0 line because some Windows application-control policies block the optional SQLAlchemy native extension in 2.1 wheels.


## Windows quick start
Double-click `START_SENTINELX.bat`. The single launcher creates the virtual environment, installs the Windows-safe dependency set, starts FastAPI, waits for `/health`, opens the UI, and writes API logs to `logs/`.

## Network discovery
Use **Network Discovery → Scan Connected Network**. The scanner selects the active Wi-Fi interface/subnet when available, combines Windows ARP/neighbor state with ICMP and TCP reachability, and reports visible IPv4 and IPv6 neighbors. It does not fabricate devices and does not brute-force scan a typical IPv6 /64.
