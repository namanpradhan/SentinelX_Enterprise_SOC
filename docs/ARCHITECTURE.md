# SentinelX Enterprise SOC v4.2.13 Architecture

```text
                    SENTINELX ENTERPRISE SOC
┌────────────────────────────────────────────────────────────────┐
│ Identity & Access                                                │
│ Admin / Employee / User • Sessions • Audit • MFA-ready IAM       │
└────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌────────────────────────────────────────────────────────────────┐
│ Telemetry & Discovery                                            │
│ Windows agent • Universal collectors • ARP • ICMP • Nmap        │
│ Suricata • Snort • network devices • cloud/mobile adapters       │
└────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌────────────────────────────────────────────────────────────────┐
│ Normalization + Detection                                       │
│ 150+ deterministic rules • Sigma-style concepts • posture        │
└────────────────────────────────────────────────────────────────┘
                              │
                ┌─────────────┴─────────────┐
                ▼                           ▼
        Correlation Engine            Risk Scoring
                │                           │
                └─────────────┬─────────────┘
                              ▼
┌────────────────────────────────────────────────────────────────┐
│ Security Intelligence                                            │
│ MITRE ATT&CK • vulnerability findings • service/version data      │
│ IDS/IPS alerts • Metasploit module intelligence                   │
└────────────────────────────────────────────────────────────────┘
                              │
             ┌────────────────┼────────────────┐
             ▼                ▼                ▼
       Incident Response   AI Analyst      Reporting / Audit
                              │
                              ▼
                 SOC Command Center Web UI
```

### Design rules

1. Deterministic detection, correlation and risk are authoritative.
2. AI is advisory and must not be the sole basis for containment.
3. Vulnerability assessment records evidence; SentinelX does not execute exploits.
4. Third-party IDS/IPS sensors remain externally managed; SentinelX consumes their telemetry.
5. Network discovery reports only what the local host can observe unless authoritative network-controller integrations are configured.
