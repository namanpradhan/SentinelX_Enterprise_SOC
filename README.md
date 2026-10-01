# SentinelX Enterprise SOC

### AI-Assisted Security Operations Center & SIEM Platform

**SentinelX** is an enterprise-oriented Security Operations Center (SOC) and Security Information and Event Management (SIEM) platform designed to centralize security telemetry, detect suspicious activity, investigate incidents, support vulnerability assessment, and assist security teams with response workflows.

It combines security monitoring, log analysis, detection engineering, threat intelligence, MITRE ATT&CK mapping, vulnerability visibility, AI-assisted investigation, and SOC workflow management in a unified platform.

> **Version:** 4.2.13  
> **Project Type:** Enterprise SOC / SIEM / Cybersecurity Research & Development  
> **Primary Language:** Python  
> **Status:** Active Development  
> **Repository:** `SentinelX_Enterprise_SOC`

---

## Overview

Modern organizations generate security events from endpoints, servers, applications, networks, cloud services, identity systems, and security tools. Without centralized visibility and structured analysis, security teams may struggle with alert volume, fragmented telemetry, investigation delays, and inconsistent response processes.

SentinelX is designed as a centralized security operations platform that brings these activities into one environment.

### SentinelX focuses on four core security workflows:

**Detect → Analyze → Respond → Protect**

The platform is designed to help security teams:

- Collect and analyze security telemetry
- Monitor security events and system activity
- Identify suspicious behavior
- Correlate security indicators
- Investigate potential incidents
- Map activity to MITRE ATT&CK techniques
- Review vulnerabilities and security exposure
- Use threat intelligence during investigations
- Generate AI-assisted investigation insights
- Support incident response workflows
- Maintain centralized SOC visibility
- Improve security monitoring and operational awareness

---

# Key Capabilities

## 1. SOC Dashboard

Provides a centralized operational view of security activity, including:

- Security events
- Alerts
- Incidents
- Threat indicators
- Vulnerability information
- System activity
- Detection results
- Investigation status
- Security metrics

The dashboard is intended to provide analysts with a single operational interface for security monitoring.

---

## 2. SIEM & Log Analysis

SentinelX provides a centralized approach to security event and log analysis.

Capabilities include:

- Security event collection
- Log ingestion
- Event normalization
- Search and filtering
- Event analysis
- Detection rule processing
- Alert generation
- Investigation support
- Security event correlation

The platform is designed to help analysts move from raw telemetry toward actionable security findings.

---

## 3. Detection Engineering

SentinelX supports security detection workflows using structured detection rules and security indicators.

Detection capabilities include:

- Suspicious process activity
- Authentication anomalies
- Network-related indicators
- Endpoint security events
- Suspicious command execution
- File activity
- Security policy violations
- Threat indicators
- Behavioral indicators

Detection logic can be extended as new threats and organizational requirements emerge.

---

## 4. MITRE ATT&CK Integration

SentinelX incorporates MITRE ATT&CK concepts to provide a structured representation of adversary behavior.

The platform can associate security findings with relevant:

- Tactics
- Techniques
- Sub-techniques
- Attack behaviors

This helps analysts understand **what an activity represents in an adversary lifecycle**, rather than treating every alert as an isolated event.

---

## 5. AI-Assisted Security Analyst

SentinelX includes an AI-assisted investigation concept intended to support security analysts during investigations.

The AI layer can assist with:

- Alert interpretation
- Event summarization
- Investigation context
- Indicator analysis
- Threat explanation
- MITRE ATT&CK context
- Investigation recommendations
- Incident summaries
- Response guidance

AI-generated information should be treated as analyst assistance rather than an authoritative security decision.

Human validation remains important for high-impact security actions.

---

## 6. Threat Intelligence

Threat intelligence capabilities are designed to help analysts enrich security investigations using indicators and contextual information.

Potential intelligence types include:

- IP addresses
- Domains
- URLs
- File hashes
- Malware indicators
- Suspicious infrastructure
- Threat actor information
- MITRE ATT&CK context

Threat intelligence can help transform isolated indicators into broader investigation context.

---

## 7. Vulnerability Assessment

SentinelX includes vulnerability-oriented security workflows for identifying and reviewing potential security weaknesses.

The vulnerability module can support:

- Asset security review
- Vulnerability visibility
- Severity classification
- Security findings
- Remediation tracking
- Exposure analysis

The project also contains defensive security intelligence related to Metasploit modules. This information is intended for authorized security assessment and research, not unauthorized exploitation.

---

## 8. IDS / IPS-Oriented Monitoring

SentinelX provides security monitoring capabilities that can be extended toward intrusion detection and prevention workflows.

The architecture is designed to support analysis of:

- Network activity
- Suspicious connections
- Security events
- Indicators of compromise
- Detection signatures
- Behavioral indicators

Network visibility depends on the telemetry and integrations available in the deployment environment.

---

## 9. Endpoint Security Visibility

The project contains endpoint-oriented components intended to support security visibility and telemetry collection.

Potential endpoint information includes:

- Processes
- Files
- Network connections
- System activity
- Security events
- Configuration information
- Suspicious behavior

Actual endpoint coverage depends on the deployed agent and configured integrations.

---

## 10. Incident Response

SentinelX supports structured incident investigation and response workflows.

Security teams can use the platform to:

1. Identify an alert
2. Investigate related events
3. Enrich indicators
4. Review affected assets
5. Analyze attacker behavior
6. Map activity to MITRE ATT&CK
7. Determine response requirements
8. Record investigation findings
9. Track remediation

Automated response actions should be carefully controlled and authorized before being enabled in production environments.

---

# SOC Workspaces

SentinelX is organized around multiple security operations workflows, including areas such as:

- SOC Dashboard
- Security Events
- Alerts
- Incidents
- Threat Intelligence
- MITRE ATT&CK
- Vulnerability Management
- Network Security
- Endpoint Security
- Detection Engineering
- Investigation
- AI Analyst
- Response Operations
- Security Analytics
- System Administration

The exact availability of individual functions depends on the current implementation and configured environment.

---

# High-Level Architecture

```text
                    ┌─────────────────────────┐
                    │       Data Sources      │
                    │                         │
                    │ Endpoints / Servers     │
                    │ Network / Applications  │
                    │ Security Tools / Cloud  │
                    └────────────┬────────────┘
                                 │
                                 ▼
                    ┌─────────────────────────┐
                    │   Telemetry Collection  │
                    │                         │
                    │ Logs / Events / Signals │
                    └────────────┬────────────┘
                                 │
                                 ▼
                    ┌─────────────────────────┐
                    │     SIEM / Analytics    │
                    │                         │
                    │ Search / Correlation    │
                    │ Detection / Analysis    │
                    └────────────┬────────────┘
                                 │
                ┌────────────────┼────────────────┐
                ▼                ▼                ▼
       ┌────────────────┐ ┌──────────────┐ ┌───────────────┐
       │ Detection      │ │ Threat Intel │ │ Vulnerability │
       │ Engine         │ │ & MITRE      │ │ Assessment    │
       └───────┬────────┘ └──────┬───────┘ └───────┬───────┘
               │                 │                 │
               └─────────────────┼─────────────────┘
                                 ▼
                    ┌─────────────────────────┐
                    │   AI Investigation     │
                    │                         │
                    │ Analysis / Summary      │
                    │ Recommendations         │
                    └────────────┬────────────┘
                                 │
                                 ▼
                    ┌─────────────────────────┐
                    │   SOC Analyst / Team    │
                    │                         │
                    │ Investigate / Respond   │
                    └────────────┬────────────┘
                                 │
                                 ▼
                    ┌─────────────────────────┐
                    │ Response & Remediation  │
                    └─────────────────────────┘
Project Structure
SentinelX_Enterprise_SOC/
│
├── .github/
│   └── workflows/
│       └── ci.yml
│
├── agent/
│   └── Endpoint and telemetry components
│
├── backend/
│   └── Backend services and APIs
│
├── data/
│   └── metasploit/
│       └── catalog.json
│
├── docs/
│   └── Documentation
│
├── frontend/
│   └── SOC web interface
│
├── logs/
│   └── Runtime/logging workspace
│
├── rules/
│   └── Security detection rules
│
├── tests/
│   └── Test suite
│
├── .env.example
├── .gitattributes
├── .gitignore
├── CHANGELOG.md
├── CHECK_SECURITY_STACK.bat
├── CHECK_SENTINELX.bat
├── CONTRIBUTING.md
├── LICENSE
├── README.md
├── README_V4.md
├── RUN_BACKEND.bat
├── RUN_FRONTEND.bat
├── SECURITY.md
├── START_SENTINELX.bat
├── START_SENTINELX.ps1
├── STOP_SENTINELX.bat
├── VERSION
└── WINDOWS_START_HERE.txt
Technology Stack

SentinelX is primarily implemented using Python with supporting web, automation, security, and infrastructure components.

Core
Python
HTML
PowerShell
Windows Batch
REST/API-oriented services
Web-based SOC interface
Security Concepts
SIEM
SOC Operations
Threat Intelligence
MITRE ATT&CK
Detection Engineering
Vulnerability Management
Incident Response
Endpoint Security
Network Security
Security Analytics
AI-Assisted Investigation
Security Frameworks & Knowledge Sources
MITRE ATT&CK
NIST Cybersecurity Framework
NIST Incident Response guidance
Security logging practices
OWASP security guidance
Windows 11 Quick Start

SentinelX includes Windows startup scripts for simplifying local execution.

Option 1 — Start SentinelX

From the project directory:

START_SENTINELX.bat

or use:

.\START_SENTINELX.ps1
Option 2 — Start Backend
RUN_BACKEND.bat
Option 3 — Start Frontend
RUN_FRONTEND.bat
Stop SentinelX
STOP_SENTINELX.bat
Manual Installation

Clone the repository:

git clone https://github.com/namanpradhan/SentinelX_Enterprise_SOC.git

Move into the project:

cd SentinelX_Enterprise_SOC

Create a virtual environment:

python -m venv .venv

Activate the environment on Windows:

.venv\Scripts\activate

Install dependencies:

pip install -r requirements.txt

Configure environment variables using the provided example:

.env.example

Create your local .env file according to the configuration required by your deployment.

Never commit .env, API keys, passwords, tokens, certificates, private keys, production logs, or other sensitive information to GitHub.

Configuration

SentinelX uses environment-based configuration where required.

A template is provided:

.env.example

Recommended approach:

.env.example
        │
        ▼
     .env
        │
        ▼
Local configuration

The .env file should remain local and must not be committed to the repository.

Validation

Before running SentinelX, the repository includes validation utilities such as:

CHECK_SENTINELX.bat

and:

CHECK_SECURITY_STACK.bat

These scripts can be used to check the local SentinelX/security environment and identify configuration or dependency issues.

Security & Responsible Use

SentinelX is intended for:

Authorized security monitoring
Defensive security research
SOC training
Cybersecurity education
Security operations development
Vulnerability assessment in authorized environments
Incident investigation
Security engineering research

Do not use SentinelX to:

Access systems without authorization
Attack third-party infrastructure
Steal credentials
Deploy malware
Conduct unauthorized exploitation
Perform destructive actions
Evade security controls
Collect private information without permission

The repository's security intelligence and vulnerability-related information should only be used within systems and environments for which the operator has explicit authorization.

Data & Privacy

SentinelX may process sensitive security telemetry depending on the deployment configuration.

Security teams should consider:

Access control
Data minimization
Log retention
Encryption
Credential protection
API key management
Audit logging
Role-based access
Secure configuration
Regulatory requirements

Do not upload real confidential organizational logs or personally identifiable information to public repositories.

Network Visibility

SentinelX's network visibility depends on the telemetry sources and integrations configured by the operator.

The platform should not be interpreted as automatically providing complete visibility into every network protocol, encrypted session, cloud environment, or endpoint.

For enterprise deployment, network visibility should be designed around the organization's existing:

Network architecture
Sensors
Firewalls
DNS infrastructure
Proxy infrastructure
Endpoint telemetry
Cloud logging
Identity systems
Security tooling
AI Security Analyst

The AI Analyst is designed as an assistance layer for security operations.

A typical workflow is:

Security Event
      │
      ▼
Detection
      │
      ▼
Alert
      │
      ▼
AI-Assisted Analysis
      │
      ├── Event Summary
      ├── Threat Context
      ├── MITRE Mapping
      ├── Indicator Analysis
      └── Investigation Guidance
      │
      ▼
Human Analyst Review
      │
      ▼
Response Decision

AI recommendations should be reviewed by qualified security personnel before high-impact actions are performed.

Threat Intelligence Workflow

SentinelX can use threat intelligence concepts to enrich investigations.

Example workflow:

Indicator
   │
   ▼
Enrichment
   │
   ├── IP Information
   ├── Domain Information
   ├── Hash Information
   ├── Threat Context
   └── MITRE ATT&CK
   │
   ▼
Risk Assessment
   │
   ▼
SOC Investigation

Threat intelligence should be validated before being used for blocking or automated response decisions.

Detection Workflow

A typical SentinelX detection workflow is:

Telemetry
   │
   ▼
Normalization
   │
   ▼
Detection Rules
   │
   ▼
Correlation
   │
   ▼
Alert
   │
   ▼
Investigation
   │
   ▼
MITRE ATT&CK Mapping
   │
   ▼
Response

Detection rules should be continuously reviewed and tuned to reduce false positives and improve detection quality.

Incident Response Workflow

SentinelX supports an investigation-oriented workflow:

1. Detect
      ↓
2. Validate
      ↓
3. Investigate
      ↓
4. Enrich
      ↓
5. Scope
      ↓
6. Contain
      ↓
7. Remediate
      ↓
8. Recover
      ↓
9. Document
      ↓
10. Improve Detection

This workflow aligns with established cybersecurity incident-response practices while remaining adaptable to organizational requirements.

Research & Academic Context

SentinelX is also developed as a cybersecurity research and academic project.

The project explores how an integrated SOC platform can combine:

SIEM
Security monitoring
Detection engineering
Threat intelligence
MITRE ATT&CK
Vulnerability visibility
AI-assisted investigation
Incident response
Security analytics

The associated academic study is based primarily on secondary research and publicly available cybersecurity literature, standards, and industry guidance.

The project should not be interpreted as claiming production-scale deployment or experimentally validated performance unless such validation is separately documented.

Design Goals

SentinelX is designed around the following principles:

Centralized Visibility

Bring relevant security information into a unified operational environment.

Analyst Assistance

Reduce repetitive investigation effort through structured analysis and AI-assisted workflows.

Explainable Security Operations

Provide context around why an event may be relevant instead of presenting isolated alerts.

Extensibility

Allow new data sources, detection rules, integrations, and security workflows to be added over time.

Human Oversight

Keep security analysts involved in important investigation and response decisions.

Secure-by-Design Development

Protect credentials, sensitive telemetry, configuration information, and deployment environments.

Future Development

Potential future improvements include:

Advanced UEBA
Additional endpoint telemetry
Expanded cloud integrations
Improved network telemetry
Advanced correlation
Detection rule management
Automated enrichment
Expanded threat intelligence integrations
Case management
Role-based access control
Advanced audit logging
Security orchestration workflows
Improved AI investigation capabilities
Automated incident timelines
Additional visualization and analytics
Enterprise deployment hardening
Performance benchmarking
Production-scale testing

Future capabilities should be validated through controlled testing before being considered production-ready.

Project Documentation

Important project documentation includes:

README.md
README_V4.md
CHANGELOG.md
SECURITY.md
CONTRIBUTING.md
WINDOWS_START_HERE.txt

These documents provide additional information about the project, security considerations, development practices, and local execution.

Version

Current release:

SentinelX Enterprise SOC v4.2.13

Version information is also maintained in:

VERSION

Changes between releases are documented in:

CHANGELOG.md
Contributing

Contributions are welcome for improvements related to:

Security detection
SOC workflows
SIEM functionality
Threat intelligence
AI-assisted investigation
Documentation
Testing
Performance
Security hardening
User interface improvements

Before submitting changes, review:

CONTRIBUTING.md

and:

SECURITY.md
Security Reporting

If you discover a security vulnerability in SentinelX, do not publicly disclose sensitive vulnerability details before responsible coordination.

Please review:

SECURITY.md

for the project's security reporting process.

License

This project is distributed under the license included in:

LICENSE

Please review the license before using, modifying, or redistributing the project.

Author

Naman Pradhan

Cyber Security Engineer

GitHub:

https://github.com/namanpradhan

Disclaimer

SentinelX is provided for cybersecurity research, education, authorized security monitoring, and defensive security purposes.

The project is not a substitute for a complete enterprise security program, professional security assessment, or qualified incident-response team.

Users are responsible for ensuring that SentinelX is deployed and operated only in environments where they have appropriate authorization.

SentinelX

Detect. Analyze. Respond. Protect.

SentinelX Enterprise SOC
AI-Assisted Security Operations Center & SIEM Platform
Version 4.2.13
