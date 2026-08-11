# GRC Compliance Assessment Tool

A unified compliance assessment tool for UK SMEs, built for the 7005SCN Individual
Research Project, MSc Cyber Security, Coventry University.

It assesses an organisation against **Cyber Essentials v3.1**, **GDPR Article 32** and
**ISO/IEC 27001:2022 Annex A** simultaneously, from a single questionnaire combined with
automatically collected technical evidence.

## What it does

- 58 mapped controls (22 Cyber Essentials, 12 GDPR Article 32, 24 ISO 27001:2022),
  of which 51 are reachable through the assessment instrument
- 34 questionnaire questions mapped to controls
- Evidence collected automatically from three sources: an Nmap network scan run via
  subprocess, a PowerShell host agent, and the questionnaire responses
- Classification by an LLM constrained to a fixed JSON schema, so output is structurally
  validated before it reaches the database
- HTML dashboard and PDF report

## Architecture

| File | Role |
|---|---|
| `main.py` | FastAPI application, questionnaire, endpoints, report generation |
| `ai_agent.py` | Anthropic API client, tool schemas, questionnaire and scan assessment passes |
| `database.py` | SQLite schema, control definitions, question-to-control mappings |
| `parsers/nmap_parser.py` | parses Nmap XML into control findings |
| `parsers/patch_parser.py` | parses Windows Update history into patch currency findings |
| `agent.ps1` | Windows host agent: patches, firewall state, local accounts, password policy, listening ports, RDP authentication |
| `baseline-audit.ps1` | independent host state capture, used to verify evaluation ground truth |
| `rq1-manual-assessment.py` | generates and scores the manual comparison sheets used in the evaluation |

## Requirements

Python 3.10+, Nmap, and a Windows host for the evidence agent.

```bash
pip install -r requirements.txt
```

WeasyPrint additionally needs system libraries:

```bash
sudo apt-get install -y libpango-1.0-0 libpangoft2-1.0-0
```

## Configuration

The Anthropic API key is read from the environment and never appears in source:

```bash
export ANTHROPIC_API_KEY="..."
```

Nmap requires root for OS detection. Grant it narrowly via sudoers rather than running
the server as root:

```
# /etc/sudoers.d/grc-nmap  (mode 440)
<user> ALL=(root) NOPASSWD: /usr/bin/nmap
```

Optional overrides:

```bash
export NMAP_TARGETS="10.0.2.20 10.0.2.30"
export WAIT_FOR_AGENT=1
```

## Running

```bash
python3 main.py
```

Then open http://127.0.0.1:8000/ and submit an assessment. Start `agent.ps1` on the
Windows host first if host evidence is required.

## Status and limitations

Research prototype, not production software. It runs in an isolated laboratory with a
single operator. Known limitations include no endpoint authentication, a permissive CORS
policy, unescaped organisation names in report templates, and unenforced SQLite foreign
keys. Host evidence collection is Windows-only. These are documented in the accompanying
report.

## Licence

MIT. See [LICENSE](LICENSE).
