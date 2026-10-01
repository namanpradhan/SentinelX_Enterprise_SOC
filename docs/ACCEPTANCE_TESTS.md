# SentinelX Acceptance Checklist

## Platform startup

- [ ] `START_SENTINELX.bat` creates or reuses `venv`.
- [ ] FastAPI reports `Application startup complete`.
- [ ] Web UI opens from FastAPI on port 8000.
- [ ] `/health` returns HTTP 200.

## Authentication and IAM

- [ ] Admin login works.
- [ ] Employee login works.
- [ ] User login works.
- [ ] Incorrect credentials are rejected.
- [ ] Role permissions are enforced by the API.
- [ ] Session countdown is visible.
- [ ] Logout revokes the active token.
- [ ] Logout-all revokes all sessions.
- [ ] Password change works and signs out other sessions.

## SOC workspaces

- [ ] Command Center renders.
- [ ] Device Fleet renders.
- [ ] Network Discovery renders.
- [ ] Threat Queue filters and sorts.
- [ ] Incident Response filters and sorts.
- [ ] Event Stream filters and sorts.
- [ ] ATT&CK Coverage renders.
- [ ] Detection Engineering filters, sorts and tests rules.
- [ ] AI Analyst opens an investigation brief.
- [ ] Reports export data and print.
- [ ] Security Center diagnostics run.

## Security data flow

- [ ] Live collector telemetry creates normalized events.
- [ ] Deterministic detections create alerts.
- [ ] Correlation creates incidents where rules support it.
- [ ] Alert status changes are audited.
- [ ] Incident status changes are audited.
- [ ] Device status changes are audited.
- [ ] Rule changes are audited.

## Network visibility

- [ ] Host interfaces are discovered.
- [ ] Wi-Fi context is displayed when Windows provides it.
- [ ] ARP/neighbor entries are parsed.
- [ ] Deep discovery runs against an authorized local subnet.
- [ ] Discovered assets appear in Device Fleet.
- [ ] The UI clearly communicates discovery boundaries.
