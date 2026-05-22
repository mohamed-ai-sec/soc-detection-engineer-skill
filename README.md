# 🛡️ SOC Detection Engineer — AI Skill v2.1.1

> **Principal-Grade Detection Rule Drafting Engine**
> Built on the [Modular AI Skill Framework](https://agentskills.io) standard

[![Version](https://img.shields.io/badge/version-2.1.1-blue)](https://github.com/mohamed-ai-sec/soc-detection-engineer-skill)
[![ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-v19-red)](https://attack.mitre.org)
[![Standard](https://img.shields.io/badge/standard-agentskills.io-green)](https://agentskills.io)
[![License](https://img.shields.io/badge/license-MIT-green)](https://github.com/mohamed-ai-sec/soc-detection-engineer-skill/blob/main/LICENSE)
[![Updated](https://img.shields.io/badge/updated-2026--05--19-lightgrey)](https://github.com/mohamed-ai-sec/soc-detection-engineer-skill/releases)

---

## What This Is

A production-grade AI skill that transforms raw detection signals into complete, multi-format detection draft packs — ready for senior engineer review and deployment.

Drop in a raw log, a MITRE technique ID, a behavior description, or a CTI report. Get back 10 rule formats, purple team validation plans, SOAR playbooks, KPIs, compliance mappings, and full detection lifecycle documentation.

**This skill accelerates detection authoring — it does not replace expert validation.**
Every output is labeled DRAFT and requires senior review before deployment.

---

## What It Produces

| Output | Details |
|--------|---------|
| **10 Rule Formats** | KQL · SIGMA · SPL · EQL · YARA · Zeek · auditd · macOS ESF · Falco · Correlation |
| **16 Phase 0 Modules** | Signal validation · MITRE mapping · evasion anticipation · FP analysis · fidelity scoring |
| **13 Pack Sections** | Metadata → Threat context → Rules → Test cases → FP guide → Triage SOP → DaC pipeline → Purple team → KPIs → Compliance → Lifecycle → Decay |
| **60 Enforcement Rules** | Anti-hallucination gates · zero invented fields · zero silent contradictions |
| **Self-Audit Declaration** | Every output ends with a PASS/PARTIAL/FAIL compliance block — visible and non-overridable |

---

## Trigger Inputs

| Input Type | Example |
|------------|---------|
| **Raw log / artifact** | Windows Event Log, Syslog, EDR telemetry, PowerShell output, file hash |
| **Natural language** | *"Write a rule for PowerShell download cradles"* |
| **MITRE technique ID** | `T1059.001`, `T1003.001`, `T1558.003` |
| **CTI report** | CISA advisory, Mandiant/CrowdStrike/MSTIC report, red team debrief |

---

## How to Use

### With Claude.ai (Recommended)

1. Open [Claude.ai](https://claude.ai)
2. Paste the full contents of `soc-detection-engineer-v2.1.1.md` as your **system prompt** or first message
3. Follow with your detection input (log, technique ID, behavior, or CTI)

### With Any OpenAI-Compatible API

```python
with open("soc-detection-engineer-v2.1.1.md", "r") as f:
    skill = f.read()

messages = [
    {"role": "system", "content": skill},
    {"role": "user", "content": "Write a detection rule for T1059.001 — PowerShell encoded command execution"}
]
```

### With the agentskills.io Framework

```yaml
skills:
  - name: soc-detection-engineer
    path: ./soc-detection-engineer-v2.1.1.md
    version: 2.1.1
```

---

## Version History

### v2.1.1 — 2026-05-19 · Precision Hardening Release
Three targeted fixes from adversarial stress-testing:

- **R60 added** — Hash anomaly claims restricted to mismatch declaration. Speculative similarity claims (e.g., *"differs in only N characters from known hash"*) are prohibited without full character-by-character verification with a stated reference hash. Prevents a dangerous forensic hallucination vector.
- **Rule C SPL fix** — Explicit enforcement: `| Comment` is invalid SPL syntax. Only the backtick `comment()` macro is compliant. Prevents silent rule failures in Splunk ES.
- **Rule B SIGMA fix** — `filter_legitimate` placeholder policy clarified: the block must be **omitted entirely** when `0J` declares zero expected FPs. Placeholder conditions in live filter blocks are prohibited. `[R-SIGMA-FILT]` compliance check added to Post-Generation Declaration.

### v2.1.0 — 2026-05-17 · Hardening Release
Major structural hardening with 16 new enforcement rules (R43–R59):
- CVE vector plausibility gate (0A-CVE)
- Contradiction resolution gate (0A-CONFLICT) with 3-outcome CVE vector check
- Detection specificity gate (0A-SPEC) with SCOPED PROCEED mode
- Platform coherence check in 0B
- Per-binary MITRE mapping enforcement (R50)
- KQL field confidence annotations (R49)
- SIGMA UUID4 enforcement + Validator Risk Block (R47, R48)
- IOC expiry maximum lifetimes (R54)
- Unknown Platform Mode (R56)
- INPUT CONFIDENCE as 7th fidelity dimension
- Purple team minimum content requirements (R57)
- Post-Generation Compliance Declaration (R58)

---

## Platform Coverage

| Platform | Rule Format | Notes |
|----------|------------|-------|
| Microsoft Sentinel / Defender XDR | KQL | Field confidence annotations per query |
| Splunk Enterprise Security | SPL | CIM-aligned; comment() macro enforced |
| Elastic Security | EQL | Stack 7.9+ |
| Universal / any SIEM | SIGMA | UUID4 enforced; pySigma conversion paths declared |
| File / Memory / Script | YARA | Scope declared per rule (PE/SCRIPT/MEMORY/DOCUMENT) |
| Network | Zeek + Suricata | |
| Linux | auditd | |
| macOS | ESF | |
| Containers / Kubernetes | Falco | IN SCOPE when container context specified |
| Windows Kernel | ETW | SilkETW + WTI provider GUID included |

---

## Key Safeguards

- **Zero invented field names** — every field maps to schema tables or is flagged `[FIELD: UNVERIFIED]`
- **Zero hallucinations** — 0A gate rejects unverifiable CVEs, nonsensical inputs, and fake MITRE IDs
- **Zero silent contradictions** — platform mismatches and format conflicts surface explicitly
- **Zero untuned rules** — every rule ships with FP context, suppression guidance, and tuning notes
- **Zero MITRE guesswork** — uncertain mappings declare `[MITRE: INSUFFICIENT EVIDENCE]`
- **Honest fidelity scoring** — 7-dimension score with INPUT CONFIDENCE adjustment; raw and adjusted both declared

---

## Compliance Mappings Included

NIST 800-53 Rev 5 · PCI DSS · HIPAA · SOC 2 · ISO 27001 · GDPR

---

## Resources

- [MITRE ATT&CK v19](https://attack.mitre.org)
- [MITRE D3FEND](https://d3fend.mitre.org)
- [SigmaHQ](https://github.com/SigmaHQ/sigma)
- [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team)
- [VECTR Purple Team Tracking](https://vectr.io)
- [Falco Rules](https://falco.org/docs/rules/)
- [agentskills.io Standard](https://agentskills.io)

---

## Disclaimer

This skill produces **expert-supervised detection drafts**. Every output requires:

- Field name verification against your live platform schema
- Threshold validation against your environment baseline
- Suppression list population from your asset inventory
- Logic testing against known TP and TN samples
- Peer review before any production alert is enabled

**Do not deploy any rule directly from this output without expert review.**

---

*SOC Detection Engineer v2.1.1 · By Mohamed Benbouazza · SOC Systems Architect*
*Compliant with [agentskills.io](https://agentskills.io) open standard*
