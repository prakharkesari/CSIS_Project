````markdown
# CIS Ubuntu 22.04 LTS Compliance Auditor

A Python-based automated compliance auditing tool for Ubuntu systems based on the CIS Ubuntu Linux 22.04 LTS Benchmark v3.0.0 (October 2025).

## Overview

This project implements an automated CIS compliance auditor covering both Ubuntu Workstation and Ubuntu Server profiles. The auditor performs security configuration checks across multiple domains including:

- Identity & Access Control
- Filesystem & Permission Integrity
- Kernel & Network Stack Hardening
- Service Surface Auditing
- Server-Specific Security Controls

The tool generates:
- Human-readable terminal output
- Structured JSON reports for automation and dashboards

## Features

- 119 CIS security checks implemented
- Supports Ubuntu 22.04 LTS and compatible with Ubuntu 24.04
- Dual-profile architecture:
  - Workstation Profile
  - Server Profile
- Three-tier severity classification:
  - T1 — Critical baseline security
  - T2 — Advanced hardening
  - T3 — Defence-in-depth
- Zero external Python dependencies
- Read-only audit design (no automatic remediation)
- JSON output for SIEM/CI-CD integration
- Recovery-mode-aware security analysis

---

# Module Coverage

| Module | Description | Checks |
|---|---|---|
| Module 1 | Identity & Access Control | 35 |
| Module 2 | Filesystem & Permission Integrity | 17 |
| Module 3 | Kernel & Network Stack Hardening | 23 |
| Module 4 | Service Surface Audit | 28 |
| Module 5 | Server-Specific Controls | 16 |

Total Checks Implemented: **119**

---

# Key Security Areas Covered

## Kernel & Network Hardening
- ASLR validation
- IPv4/IPv6 sysctl hardening
- ICMP redirect protection
- Source routing prevention
- Reverse path filtering
- Dangerous protocol blacklisting

## AppArmor Auditing
- AppArmor installation checks
- Disabled profile detection
- Complain-mode profile detection

## Boot Security
- GRUB bootloader permission auditing

## Service Hardening
- SSH hardening checks
- Firewall validation
- Legacy service detection

## Physical Attack Surface Reduction
- Wireless interface detection
- USB storage blocking
- FireWire module blacklisting

---

# Architecture

The auditor uses:
- Native Python file parsing
- Live system state collection
- sysctl runtime + persistent configuration validation
- subprocess-based system inspection

Outputs:
- `module_N_results.json`
- Color-coded terminal summary

---

# Example Output

```json
{
  "cis_id": "1.4.2",
  "title": "Ensure permissions on bootloader config are configured",
  "status": "FAIL",
  "message": "/boot/grub/grub.cfg is world-readable.",
  "vulnerability": "Attackers may tamper with boot parameters.",
  "tier": 1
}
````

---

# Requirements

* Ubuntu 22.04 LTS / 24.04
* Python 3.8+
* Root privileges (`sudo`)

No external Python packages required.

---

# Running the Auditor

```bash
sudo python3 module1..5.py
```

Example:

```bash
sudo python3 WorkstationOS/module1..5.py
```

or

```bash
sudo python3 ServerOS/module1..5.py
```

---

# Design Principles

* Read-only auditing
* No automatic remediation
* Accurate PASS/FAIL/N/A handling
* Recovery-mode-aware analysis
* Persistent configuration validation

---

# Team Contributions

### Aman (2024202015)

* Module 1 — Identity & Access Control
* Module 5 — Server-Specific Controls

### Abhradeep Das (2024202018)

* Module 2 — Filesystem & Permission Integrity
* Module 4 — Service Surface Audit

### Prakhar Kesari (2024202023)

* Module 3 — Kernel & Network Stack Hardening
* sysctl dual-state checking framework
* Recovery mode analysis

---

# Future Work

* Full auditd / logging rule parser
* CIS Section 6 implementation
* Automated remediation support
* Dashboard integration
* CI/CD pipeline enforcement

---

# Disclaimer

This tool is intended for educational and auditing purposes only. It does not modify system configurations automatically.

---

# References

* CIS Ubuntu Linux 22.04 LTS Benchmark v3.0.0
* CIS Controls v8
* Ubuntu Security Documentation

```
```
