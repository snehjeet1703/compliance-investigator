# AI-Powered Compliance Investigation Platform

An evidence-driven security investigation tool that processes raw security logs, detects attack patterns, correlates findings across multiple sources, maps to compliance frameworks, and generates investigation reports with AI-powered analysis.

Built from scratch as a hands-on learning project — from zero Python experience to a working multi-source investigation platform.

## What It Does

Feed it raw log files. Get an investigation report.

The platform processes security logs through a structured pipeline:

**Normalize** — Parses CloudTrail JSON, Linux auth.log, and application admin logs into a unified event schema.

**Timeline** — Sorts events chronologically and groups them into user sessions, revealing activity patterns.

**Detect** — Runs 14 detection rules across events, identifying suspicious behavior from individual actions to multi-event patterns like impossible travel and volume anomalies.

**Correlate** — Links related findings into attack chains, connecting actions across different user accounts and time windows.

**Compliance** — Maps every finding to specific controls in ISO 27001:2022, SOC 2, and India's DPDP Act 2023, showing which controls failed and why.

**Cross-Source Analysis** — When multiple log files are provided, identifies what each source uniquely captured that the other missed.

**AI Analysis** — Uses a local LLM (Ollama) for executive summaries, root cause analysis, and an interactive investigation chat.

**Report** — Generates a structured investigation report in Markdown with findings, attack chains, compliance impact, confidence ratings, and evidence gaps.

## Detected Attack Patterns

The platform detects and correlates these attack types:

| Scenario | Chain Type | Key Signals |
|----------|-----------|-------------|
| Insider creating backdoor accounts | `ACCOUNT_CREATION_ATTACK` | User creation, admin policy attachment, data access via new account, self-deletion |
| Compromised credentials via phishing | `COMPROMISED_CREDENTIALS` | Concurrent sessions from different IPs, impossible travel, MFA bypass |
| Departing employee data theft | `DATA_HOARDING` | Download volume anomaly, breadth anomaly across buckets, access key persistence |
| SSH brute force with compromise | `SSH_COMPROMISE` | Failed login patterns, credential theft, backdoor user creation, audit log tampering |
| Multiple failed logins then action | `BRUTE_FORCE_AND_ACT` | Repeated login failures followed by privilege escalation |

## Detection Rules

**Per-Event Rules:**
- Login without MFA
- Privilege escalation (user creation, policy attachment, access key creation)
- CloudTrail / audit trail tampering
- Sensitive data access (keyword-based bucket/file matching)
- Activity during unusual hours
- Account self-deletion

**Multi-Event Rules:**
- Concurrent sessions (same user, different IPs within 30 minutes)
- Impossible travel (same user in different AWS regions within 60 minutes)
- IP anomaly (activity from untrusted IPs, baselined against MFA-authenticated sessions)
- Persistence detection (access key creation for own account)
- Download volume anomaly (compared against peer behavior)
- Access breadth anomaly (unusual number of distinct data sources)
- SSH brute force (failed login threshold with success tracking)
- Suspicious sudo commands (pattern-matched against known attack indicators)

## Compliance Frameworks

Each finding maps to specific controls with the requirement text, how the control failed, and the supporting evidence:

- **ISO 27001:2022** — Annex A controls including A.5.15 (Access Control), A.8.5 (Secure Authentication), A.8.15 (Logging), A.5.34 (PII Protection), and others
- **SOC 2** — Trust Services Criteria including CC6.1 (Logical Access), CC6.3 (Access Management), CC7.2 (Monitoring)
- **DPDP Act 2023** — Section 8(4) (Reasonable Security Safeguards), Section 8(6) (Breach Notification)

Frameworks are defined as JSON files, making it straightforward to add GDPR, PCI DSS, HIPAA, or others.

## Supported Log Formats

| Format | File Type | Source |
|--------|-----------|--------|
| AWS CloudTrail | `.json` | Cloud infrastructure audit logs |
| Linux auth.log | `.log` | SSH logins, sudo commands, authentication events |
| Application admin logs | `.log` | Admin portal logins, data exports, configuration changes |

The normalizer architecture is modular — each format has its own parser that outputs the same event schema, so adding new log formats requires only a new normalizer file.

## Project Structure

```
compliance-investigator/
├── app.py                    # Streamlit web UI
├── main.py                   # CLI orchestrator
├── normalizer.py             # CloudTrail JSON parser
├── linux_normalizer.py       # Linux auth.log parser
├── app_normalizer.py         # Application log parser
├── timeline.py               # Timeline building + session grouping
├── detector.py               # Detection rules + attack chain correlation
├── compliance.py             # Framework mapping engine
├── correlator.py             # Cross-source correlation
├── ai_engine.py              # Local AI integration (Ollama)
├── investigator.py           # Interactive investigation mode
├── report_generator.py       # Markdown report generation
├── compliance_mappings/
│   ├── iso27001.json
│   ├── soc2.json
│   └── dpdp.json
├── cloudtrail_50.json        # Sample: insider threat scenario
├── scenario_phishing.json    # Sample: compromised credentials
├── scenario_departing_employee.json  # Sample: data hoarding
├── linux_auth.log            # Sample: SSH brute force
├── app_admin.log             # Sample: admin portal (cross-source)
└── progress.md               # Build log
```

## Getting Started

### Prerequisites

- Python 3.12+
- Ollama (for AI features)

### Installation

```bash
git clone https://github.com/YOUR_USERNAME/compliance-investigator.git
cd compliance-investigator
pip install python-dateutil requests streamlit
```

### Install Ollama (for AI features)

Download from [ollama.com](https://ollama.com), then pull the model:

```bash
ollama pull llama3.2
```

### Run the Web UI

```bash
python -m streamlit run app.py
```

Upload one or more log files and click **Run Investigation**.

### Run from Command Line

```bash
python main.py
```

Edit `log_files` in `main.py` to specify which files to analyze.

## Sample Investigation Output

Running the insider threat scenario (`cloudtrail_50.json`) produces:

- **50 events** normalized and sorted
- **16 sessions** identified
- **19 findings** across CRITICAL, HIGH, and MEDIUM severity
- **2 attack chains** — account creation attack + brute force pattern
- **18 compliance controls failed** across 3 frameworks
- **AI-generated** executive summary and root cause analysis
- **Full investigation report** in Markdown

Merging with the application admin log (`app_admin.log`) adds:

- **86 merged events** from 2 sources
- **Cross-source correlation** revealing admin portal actions invisible to CloudTrail (bulk data exports with file sizes and record counts, audit notification changes, data retention policy modifications)

## How It Works

### Investigation Pipeline

```
Log Files (any format)
    ↓
Normalizers (format-specific → unified schema)
    ↓
Timeline Engine (sort → session grouping → summaries)
    ↓
Detection Engine (per-event rules → multi-event rules)
    ↓
Chain Correlator (link findings → identify attack patterns)
    ↓
Compliance Mapper (findings → framework controls → evidence)
    ↓
Cross-Source Correlator (compare sources → find gaps)
    ↓
AI Analysis (executive summary → root cause → interactive chat)
    ↓
Investigation Report (Markdown with all sections)
```

### Normalized Event Schema

Every log format is parsed into this common structure:

```python
{
    "timestamp": datetime,      # When
    "actor": str,               # Who
    "action": str,              # What they did
    "service": str,             # Through what service
    "source_ip": str,           # From where
    "region": str,              # AWS region or hostname
    "target": str,              # What it was done to
    "mfa_used": str,            # Authentication method
    "source_file": str,         # Which log source
    "raw": dict/str             # Original event for reference
}
```

### Adding a New Log Format

1. Create a new normalizer file (e.g., `gcp_normalizer.py`)
2. Implement `load_*_logs()` and `normalize_all_*()` functions
3. Parse each event into the schema above
4. Add the format detection to `main.py` and `app.py`

Existing detection rules, compliance mapping, and reporting work automatically with the new format.

### Adding a Compliance Framework

1. Create a JSON file in `compliance_mappings/` (e.g., `gdpr.json`)
2. Map detection rule names to framework controls
3. Include control ID, title, requirement text, and failure description

The compliance engine picks up new frameworks automatically.

## Investigation Principles

The platform follows structured investigative methodology:

- **Evidence-based** — every conclusion traces back to specific log events
- **Facts vs. inferences** — detection rules produce facts; AI analysis is clearly labeled as inference
- **Confidence awareness** — reports include confidence ratings, assumptions, and evidence gaps
- **Root cause depth** — asks "why" repeatedly to reach organizational and technical root causes
- **Defense in depth** — maps findings to multiple frameworks simultaneously

## Limitations

- **AI accuracy** — the local LLM (llama3.2 8B) sometimes misattributes actions between actors; AI output should be verified against rule-based findings
- **Static analysis** — processes exported log files, not live log streams; designed for post-incident investigation, not real-time monitoring
- **Detection coverage** — rules cover common attack patterns; novel attack techniques may not trigger existing rules
- **Log completeness** — analysis quality depends on the completeness and integrity of the input logs

## Built With

- **Python** — core pipeline and detection logic
- **Streamlit** — web interface
- **Ollama + llama3.2** — local AI analysis
- **python-dateutil** — timestamp parsing across formats

No cloud APIs, no external dependencies for core functionality. Everything runs locally.

## Background

This project was built as a hands-on learning exercise by a GRC professional exploring the intersection of security investigations, digital forensics, compliance automation, and AI. The goal was to learn by building rather than by studying — every module represents a real investigation concept implemented from scratch.

The development journey is documented in `progress.md`.

## License

MIT
