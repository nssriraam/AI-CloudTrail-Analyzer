# AI-Powered CloudTrail Anomaly Detector

## Overview
A local AI-powered security tool that analyzes AWS CloudTrail logs and performs 
automated SOC-style threat detection using a locally running LLM (Qwen 2.5 via Ollama).
No cloud API calls — fully offline, fully private.

## What It Does
- Parses AWS CloudTrail JSON logs (20+ events)
- Sends each event to a local LLM for SOC-style analysis
- Returns severity rating, suspicion assessment, MITRE ATT&CK mapping, and recommended action per event
- Generates a structured incident report automatically

## Tools & Technologies
- Python 3
- Ollama (local LLM runtime)
- Qwen 2.5 Coder 7B (local AI model)
- AWS CloudTrail JSON log format

## Project Structure
```
cloudtrail-ai-analyzer/
├── logs/
│   └── cloudtrail.json       # CloudTrail log input (20 simulated events)
├── analyzer.py               # Main analysis script
├── report.txt                # Auto-generated SOC incident report
└── README.md
```

## Simulated Attack Scenario
The sample log file simulates a realistic AWS attack chain across 20 events:

| Phase | Events | What Happened |
|---|---|---|
| Initial Access | evt-002/003/004 | Brute-force login attempts from external IP |
| Persistence | evt-006/007 | Backdoor user created, AdminAccess policy attached |
| Defense Evasion | evt-009/010 | CloudTrail trails deleted and logging stopped |
| Discovery | evt-011/012 | S3 buckets enumerated, ACLs inspected |
| Exfiltration Attempt | evt-013/018 | S3 bucket made public, sensitive data access attempted |
| Credential Access | evt-014/015 | Access key created, org-level role assumed |
| Impact | evt-019/020 | Sensitive data deleted, rogue VPC created in foreign region |

## Sample Output
Each event is analyzed and returns:
- **SEVERITY**: LOW / MEDIUM / HIGH / CRITICAL
- **SUMMARY**: What happened in plain English
- **SUSPICION**: Why it may or may not be suspicious
- **MITRE_TECHNIQUE**: Mapped ATT&CK technique where applicable
- **RECOMMENDED_ACTION**: SOC analyst next steps

### Example — High Severity Detection
```
Event: AttachUserPolicy | Time: 2024-03-10T07:35:10Z
Source IP: 192.168.1.105 | Identity: IAMUser

SEVERITY: HIGH
SUMMARY: The IAM user "admin" attached AdministratorAccess policy to "backdoor-user"
SUSPICION: Highly suspicious — grants full admin privileges to a newly created user
MITRE_TECHNIQUE: Privilege Escalation (T1054)
RECOMMENDED_ACTION: Revoke policy immediately, investigate admin account for compromise
```

## How To Run

1. Install Ollama and pull Qwen model:
```bash
ollama pull qwen2.5-coder:7b
```

2. Install Python dependency:
```bash
pip install requests
```

3. Place your CloudTrail JSON log in `logs/cloudtrail.json`

4. Run the analyzer:
```bash
python analyzer.py
```

5. Review output in terminal and `report.txt`

## Skills Demonstrated
- AWS CloudTrail log analysis and threat detection
- AI/LLM integration for security automation
- SOC alert triage and incident reporting
- MITRE ATT&CK framework mapping
- Attack chain reconstruction from log events
- Python scripting for security tooling
- Offline/local AI deployment for privacy-sensitive security work
