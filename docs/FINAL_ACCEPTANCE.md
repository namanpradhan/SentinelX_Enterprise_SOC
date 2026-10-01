# SentinelX Enterprise SOC v4.2.13 — Final Acceptance Checklist

## Core service
- FastAPI starts on `127.0.0.1:8000`.
- `/health` returns `status=healthy`.
- SQLite database initializes under `backend/data` unless `SENTINELX_DB_PATH` is set.
- Swagger is available at `/docs`.

## IAM
- Admin, Employee and User roles work.
- Logout and logout-all work.
- Session expiry and idle timeout are server-enforced.
- Password hashing uses PBKDF2-SHA256.
- Administrative actions are audited.

## SOC workspaces
- Command Center
- Device Fleet
- Network Discovery
- Threat Queue
- Incident Response
- Event Stream
- ATT&CK Coverage
- Detection Engineering
- AI Analyst
- Vulnerability Scanner
- IDS / IPS
- Exploit Intelligence
- Identity & Access
- Reports & Export
- Security Center

## Security integrations
- Nmap detection is surfaced in Vulnerability Scanner and Network Discovery.
- Suricata/Snort sensor status and alert ingestion are surfaced in IDS / IPS.
- Metasploit module intelligence is searchable without exposing exploit execution.
- Ollama status/models are shown in AI Analyst; deterministic fallback remains available.

## Acceptance tests
Run:

```powershell
python tests/smoke_test.py
python tests/full_acceptance.py
node --check frontend/app.js
```

For optional browser validation, run `tests/browser_smoke.py` on a Windows workstation with Chromium/Playwright available.
