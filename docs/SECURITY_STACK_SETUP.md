# SentinelX Security Stack Integration

SentinelX v4.2.8 provides integration surfaces for **Nmap, Suricata, Snort 3, Metasploit Framework and Ollama**. It does not bundle third-party binaries or third-party commercial/community rules.

## Nmap
Nmap is used for local discovery and service/version assessment. On Windows, install Nmap from the official Nmap download page and keep Npcap enabled in the installer. SentinelX detects `nmap.exe` automatically when it is on `PATH`.

Official source: https://nmap.org/download.html

## Suricata
SentinelX can read Suricata EVE JSON alerts when `SENTINELX_SURICATA_EVE_LOG` points to the configured EVE JSON file. Example local SentinelX rules are in `rules/suricata/local.rules`.

Suricata supports both IDS and inline IPS deployments. Inline enforcement should be tested on a controlled network segment before production use.

Official docs: https://docs.suricata.io/

## Snort 3
SentinelX can report Snort 3 availability and consume a configured alert JSON feed. Example local rules are in `rules/snort/local.rules`.

Snort 3 uses rule files to drive its detection/IPS behavior.

Official docs: https://docs.snort.org/

## Metasploit Framework
SentinelX provides a module-intelligence catalog and detects a locally installed `msfconsole`. The SentinelX UI intentionally does **not** expose exploit execution, payload generation, reverse shells, brute-force modules or destructive actions. Use Metasploit independently in an explicitly authorized lab or assessment environment.

Official docs: https://docs.rapid7.com/metasploit/

## Ollama
SentinelX checks the local Ollama API and lists installed models. When Ollama is unavailable, AI Analyst automatically falls back to deterministic analyst guidance.

Configure:

- `SENTINELX_OLLAMA_URL`
- `SENTINELX_OLLAMA_MODEL`
- `SENTINELX_AI_MODELS`

## Important network-visibility boundary

A Windows client cannot reliably enumerate every Wi-Fi client associated with an access point when the AP uses client isolation, VLAN separation, sleeping clients or controller-side policy. For authoritative enterprise inventory, add the network controller/AP connector and endpoint agents. SentinelX therefore distinguishes **host-visible peers** from **controller-authoritative device inventory**.
