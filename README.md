# File System Security Research Project

> A research-oriented security assessment project focused on empirical analysis of file system attack surfaces, integrity monitoring, access pattern anomaly detection, privilege escalation pathways, and forensic timeline reconstruction.

## Overview

This project goes beyond basic tool usage to conduct **structured security research** on file system vulnerabilities. It includes a full research paper, five purpose-built Python analysis tools, and a controlled test environment with intentional misconfigurations.

### Research Questions Addressed

| # | Research Question |
|---|------------------|
| RQ1 | What are the most common file system permission misconfigurations, and how can they be detected? |
| RQ2 | How effective is hash-based integrity monitoring at detecting unauthorized modifications? |
| RQ3 | Can statistical analysis of access patterns identify anomalous behavior? |
| RQ4 | What file system conditions create exploitable privilege escalation pathways? |
| RQ5 | How can forensic timeline reconstruction from file metadata aid incident response? |

## Project Structure

```
file-system-security-research/
├── research-paper.md              # Full research paper (STRIDE analysis, CVE data, experiments)
├── README.md                      # This file
├── scripts/
│   ├── 01_permission_audit.py     # E1: Permission misconfiguration scanner
│   ├── 02_integrity_monitor.py    # E2: SHA-256 file integrity monitoring
│   ├── 03_access_pattern_analyzer.py  # E3: Audit log anomaly detection
│   ├── 04_privilege_escalation_check.py  # E4: Priv-esc pathway finder
│   └── 05_forensic_timeline.py    # E5: MACB forensic timeline builder
├── data/
│   └── sample_audit_log.txt       # Synthetic audit log with embedded anomalies
├── results/                       # Output directory for experiment results
├── setup_environment.ps1          # Windows setup (creates test sandbox)
└── setup_environment.sh           # Linux setup (creates test sandbox)
```

## Quick Start

### Prerequisites

- **Python 3.6+** (no external packages required — stdlib only)
- **Windows 10/11** or **Linux (Ubuntu 22.04+)**

### Step 1: Set Up the Test Environment

**Windows (PowerShell):**
```powershell
cd file-system-security-research
.\setup_environment.ps1
```

**Linux / WSL:**
```bash
cd file-system-security-research
chmod +x setup_environment.sh
sudo ./setup_environment.sh
```

This creates a `test_sandbox/` directory with files containing **10 intentional security misconfigurations** for the experiments to detect.

### Step 2: Run the Experiments

```bash
# E1: Permission Audit — Find misconfigured permissions
python scripts/01_permission_audit.py ./test_sandbox

# E2: Integrity Monitor — Create baseline, then detect tampering
python scripts/02_integrity_monitor.py --init ./test_sandbox
echo "tampered" >> ./test_sandbox/config/app.conf
python scripts/02_integrity_monitor.py --check ./test_sandbox

# E3: Access Pattern Analysis — Detect anomalies in audit logs
python scripts/03_access_pattern_analyzer.py data/sample_audit_log.txt

# E4: Privilege Escalation Check — Find escalation pathways
python scripts/04_privilege_escalation_check.py ./test_sandbox

# E5: Forensic Timeline — Reconstruct file system events
python scripts/05_forensic_timeline.py ./test_sandbox
```

### Step 3: Review Results

All output is saved to the `results/` directory:

| File | Description |
|------|-------------|
| `permission_audit_report.csv` | CSV of permission anomalies by severity |
| `integrity_baseline.json` | SHA-256 baseline snapshot |
| `integrity_check_report.txt` | File modification detection report |
| `access_anomaly_report.txt` | Anomaly scores and flagged events |
| `privesc_report.txt` | Categorized escalation vectors |
| `forensic_timeline.csv` | Chronological MACB timeline |
| `forensic_timeline_report.txt` | Timeline analysis summary |

## Research Paper

The full research paper (`research-paper.md`) covers:

- **Literature Review** — NIST SP 800-123/800-53, CIS Benchmarks, MITRE ATT&CK, academic references
- **Threat Model** — STRIDE analysis of file system attack surfaces with attack trees
- **CVE Analysis** — 2020–2025 data showing 60%+ of FS-related CVEs involve privilege escalation
- **5 Experiments** — Methodology, expected results, and research significance
- **Hardening Recommendations** — Actionable checklist derived from experimental findings
- **Tool Comparison** — Our scripts vs. Tripwire, AIDE, OSSEC, auditd

## Design Principles

1. **Zero dependencies** — All scripts use only the Python 3 standard library
2. **Cross-platform** — Works on both Windows and Linux
3. **Non-destructive** — All experiments run in an isolated sandbox
4. **Research-oriented** — Structured output (CSV, JSON) for further analysis
5. **Defensive focus** — Tools are designed for assessment, not exploitation

## References

Key standards and frameworks referenced:
- NIST SP 800-123 (General Server Security)
- NIST SP 800-53 Rev. 5 (Security Controls)
- CIS Benchmarks for Ubuntu Linux
- MITRE ATT&CK Framework
- GTFOBins (SUID exploitation reference)

## License

This project is for **educational and research purposes only**. All credentials, keys, and tokens in the test sandbox are dummy/synthetic data.
