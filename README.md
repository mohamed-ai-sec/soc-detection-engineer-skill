# 🛡️ SOC Detection Engineer — AI Skill v2.1.1

> **AI-Assisted Detection Engineering Framework for Structured Rule Drafting**  
> Built on the [Modular AI Skill Framework](https://agentskills.io) standard

[![Version](https://img.shields.io/badge/version-2.1.1-blue)](https://github.com/mohamed-ai-sec/soc-detection-engineer-skill)
[![ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-v19-red)](https://attack.mitre.org)
[![Standard](https://img.shields.io/badge/standard-agentskills.io-green)](https://agentskills.io)
[![License](https://img.shields.io/badge/license-MIT-green)](https://github.com/mohamed-ai-sec/soc-detection-engineer-skill/blob/main/LICENSE)
[![Updated](https://img.shields.io/badge/updated-2026--05--19-lightgrey)](https://github.com/mohamed-ai-sec/soc-detection-engineer-skill/releases)

---

## ⚠️ Operational Disclaimer

This framework generates **draft detection logic only**.

It is designed to assist SOC and detection engineering workflows, not replace expert analysis or production validation.

All outputs require:
- Validation against your SIEM / EDR schema
- Threshold tuning based on environment baselines
- False positive testing using known-good datasets
- Senior engineer or peer review before deployment

---

## What This Is

An AI-assisted detection engineering framework that transforms raw security inputs into structured, multi-format detection drafts.

It supports structured analysis of:
- Security logs and telemetry
- MITRE ATT&CK technique IDs
- Behavioral threat descriptions
- Threat intelligence reports (CTI)

---

## What It Produces

| Output | Details |
|--------|---------|
| **10 Rule Formats** | KQL · SIGMA · SPL · EQL · YARA · Zeek · auditd · macOS ESF · Falco · Correlation |
| **16 Phase 0 Modules** | Signal validation · MITRE mapping · evasion analysis · false positive modeling · fidelity scoring |
| **13 Pack Sections** | Metadata → Threat context → Rules → Test cases → FP guide → Triage SOP → Deployment notes → Purple team → KPIs → Compliance → Lifecycle → Decay |
| **60 Enforcement Rules** | Schema validation · contradiction detection · hallucination prevention |
| **Self-Audit Layer** | Each output includes PASS / PARTIAL / FAIL validation summary |

---

## Trigger Inputs

| Input Type | Example |
|------------|---------|
| **Raw log / artifact** | Windows Event Log, Syslog, EDR telemetry |
| **Natural language** | “Write a rule for PowerShell download cradle detection” |
| **MITRE technique ID** | `T1059.001`, `T1003.001`, `T1558.003` |
| **CTI report** | CISA advisory, vendor threat reports, red team findings |

---

## How to Use

### With Claude.ai (Recommended)

1. Open [Claude.ai](https://claude.ai)
2. Paste `soc-detection-engineer-v2.1.1.md` as system prompt or first message
3. Provide detection input (log, MITRE ID, or behavior description)

---

### With OpenAI-Compatible APIs

```python
with open("soc-detection-engineer-v2.1.1.md", "r") as f:
    skill = f.read()

messages = [
    {
        "role": "system",
        "content": skill
    },
    {
        "role": "user",
        "content": "Write a detection rule for T1059.001 — PowerShell encoded command execution"
    }
]
