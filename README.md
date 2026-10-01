# SentinelX Enterprise SOC

### AI-Assisted Security Operations Center & SIEM Platform

SentinelX is an enterprise-oriented cybersecurity platform designed to centralize security monitoring, SIEM, threat detection, vulnerability visibility, threat intelligence, incident investigation, and AI-assisted security analysis.

**Version:** 4.2.13  
**Technology:** Python, HTML, PowerShell, Windows Batch  
**Project:** Cybersecurity / SOC / SIEM

---

## 🚀 Key Features

- 🛡️ Security Operations Center (SOC)
- 📊 SIEM & security event monitoring
- 🔎 Security alert detection and analysis
- 🤖 AI-assisted security investigation
- 🎯 MITRE ATT&CK mapping
- 🌐 Network security visibility
- 💻 Endpoint security monitoring
- 🔥 Threat intelligence
- ⚠️ Vulnerability assessment
- 🚨 Incident investigation and response
- 📈 Security analytics and dashboards
- 🔐 Secure configuration and access practices

---

## 🏗️ Architecture

```text
Data Sources
     │
     ▼
Telemetry / Logs
     │
     ▼
SIEM & Analytics
     │
     ├── Detection Engine
     ├── Threat Intelligence
     ├── MITRE ATT&CK
     └── Vulnerability Assessment
             │
             ▼
      AI-Assisted Analysis
             │
             ▼
       SOC Analyst Review
             │
             ▼
      Response & Remediation

## Project Structure

SentinelX_Enterprise_SOC/
├── .github/workflows/
├── agent/
├── backend/
├── data/
├── docs/
├── frontend/
├── logs/
├── rules/
├── tests/
├── .env.example
├── CHANGELOG.md
├── CONTRIBUTING.md
├── SECURITY.md
├── LICENSE
├── VERSION
├── START_SENTINELX.bat
├── START_SENTINELX.ps1
├── RUN_BACKEND.bat
├── RUN_FRONTEND.bat
├── STOP_SENTINELX.bat
└── README.md


## 💻 Windows Quick Start

## From the project directory:

START_SENTINELX.bat

## PowerShell:

.\START_SENTINELX.ps1

## Backend:

RUN_BACKEND.bat

## Frontend:

RUN_FRONTEND.bat

## Stop:

STOP_SENTINELX.bat
⚙️ Manual Installation

## Clone the repository:

git clone https://github.com/namanpradhan/SentinelX_Enterprise_SOC.git
cd SentinelX_Enterprise_SOC

## Create virtual environment:

python -m venv .venv

## Activate on Windows:

.venv\Scripts\activate

## Install dependencies:

pip install -r requirements.txt

## Configure the environment using:

.env.example

## Create a local .env file as required.

Never commit passwords, API keys, tokens, certificates, private keys, .env, or confidential logs to GitHub.

## 🔍 Validation

## Use the included validation scripts:

CHECK_SENTINELX.bat
CHECK_SECURITY_STACK.bat

## These help verify the local SentinelX and security environment.

🤖 AI Security Analyst

## The AI Analyst is designed as an assistance layer for SOC investigations.

Security Event
      ↓
Detection
      ↓
Alert
      ↓
AI-Assisted Analysis
      ↓
Human Analyst Review
      ↓
Response Decision

## AI recommendations should be reviewed by qualified security personnel before high-impact actions.

## 🎯 Security Workflow
Detect
  ↓
Analyze
  ↓
Enrich
  ↓
Investigate
  ↓
MITRE ATT&CK Mapping
  ↓
Respond
  ↓
Remediate

## 🔐 Responsible Use

## SentinelX is intended for:

Authorized security monitoring
Cybersecurity research
SOC training
Security education
Defensive security testing
Authorized vulnerability assessment
Incident investigation

Do not use the platform for unauthorized access, attacks, credential theft, malware deployment, destructive activity, or unauthorized exploitation.

## 📚 Research Context

SentinelX is also an academic cybersecurity project exploring the integration of:

SIEM
SOC operations
Detection engineering
Threat intelligence
MITRE ATT&CK
Vulnerability management
AI-assisted investigation
Incident response
Security analytics

## The associated academic study is based primarily on secondary research and publicly available cybersecurity standards, literature, and industry guidance.

## 🔮 Future Development

Planned areas include:

Advanced UEBA
Additional endpoint telemetry
Cloud integrations
Improved network visibility
Advanced correlation
Automated enrichment
Case management
RBAC
Security orchestration
Improved AI investigation
Performance benchmarking

## 📖 Documentation

See:

README_V4.md
CHANGELOG.md
SECURITY.md
CONTRIBUTING.md
WINDOWS_START_HERE.txt

## 👨‍💻 Author

## Naman Pradhan
Cyber Security Engineer

## GitHub:
https://github.com/namanpradhan

## 📜 License

See the LICENSE file for licensing information.

## ⚠️ Disclaimer

SentinelX is provided for cybersecurity research, education, and authorized defensive security purposes.

Users are responsible for ensuring that the platform is operated only in environments where they have appropriate authorization.
