# SentinelX Windows Agent 4.2.8

This is a starter endpoint telemetry collector for authorized Windows endpoints.

It collects selected Windows Security / PowerShell / process telemetry and sends normalized events to:

`POST /collectors/ingest`

Configure the server with `SENTINELX_AGENT_KEY` and configure the same key on the endpoint. Run only on systems you are authorized to monitor.

The agent intentionally collects a limited set of telemetry for the MCA project baseline. A production endpoint sensor should add signed updates, certificate-based device identity, tamper resistance, queueing/retry, local buffering, privacy controls and secure TLS deployment.
