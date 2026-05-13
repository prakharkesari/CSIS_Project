#!/usr/bin/env python3
"""
Module 3 — Kernel & Network Stack Hardening
CIS Ubuntu 22.04 LTS Benchmark v3.0.0 | Checks #53–75
"""
import os
import sys
import json
import glob
import subprocess

# ==========================================
# 0. EXECUTION CONTEXT VERIFICATION
# ==========================================
if os.geteuid() != 0:
    print("FATAL: This script must be executed as root (sudo python3 module3.py)")
    sys.exit(1)

# ==========================================
# 1. NATIVE PARSERS — Load data once into memory
# ==========================================

def get_live_sysctl(key):
    """Read live kernel param from /proc/sys/ without invoking sysctl binary."""
    path = "/proc/sys/" + key.replace('.', '/')
    try:
        with open(path, 'r') as f:
            return f.read().strip()
    except FileNotFoundError:
        return None
    except Exception as e:
        return f"ERROR:{e}"

def get_disk_sysctl_config():
    """
    Parse all persistent sysctl configs respecting systemd load order.
    Returns dict of {key: value} with last-writer-wins semantics.
    """
    config = {}
    paths = ['/usr/lib/sysctl.d/*.conf', '/etc/sysctl.d/*.conf', '/etc/sysctl.conf']
    files = []
    for p in paths:
        if '*' in p:
            files.extend(sorted(glob.glob(p)))
        elif os.path.isfile(p):
            files.append(p)
    for fp in files:
        try:
            with open(fp, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#') or line.startswith(';'):
                        continue
                    if '=' in line:
                        k, v = line.split('=', 1)
                        config[k.strip()] = v.strip()
        except PermissionError:
            pass
    return config

def get_modprobe_config():
    """
    Aggregate all /etc/modprobe.d/*.conf lines into memory.
    Returns list of normalized lines.
    """
    lines = []
    for fp in sorted(glob.glob('/etc/modprobe.d/*.conf')):
        try:
            with open(fp, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        lines.append(' '.join(line.split()))
        except PermissionError:
            pass
    return lines

def get_limits_config():
    """
    Aggregate /etc/security/limits.conf and limits.d/*.conf into one list.
    """
    lines = []
    files = ['/etc/security/limits.conf'] + sorted(glob.glob('/etc/security/limits.d/*.conf'))
    for fp in files:
        try:
            with open(fp, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        lines.append(' '.join(line.split()))
        except (FileNotFoundError, PermissionError):
            pass
    return lines

def is_package_installed(pkg):
    """Check dpkg status natively by reading /var/lib/dpkg/info/<pkg>.list."""
    return os.path.isfile(f'/var/lib/dpkg/info/{pkg}.list')

def check_service_active(service):
    """Query systemd without shell injection."""
    try:
        r = subprocess.run(
            ['systemctl', 'is-active', service],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True
        )
        return r.stdout.strip() == 'active'
    except Exception:
        return False

# ==========================================
# 2. AUDIT FUNCTIONS
# ==========================================

def _sysctl_check(cis_id, title, key, expected_val, disk_config, tier=2,
                  vulnerability="Misconfigured kernel parameter weakens system security."):
    """Generic helper: checks both live value AND disk persistence."""
    live = get_live_sysctl(key)
    persisted = disk_config.get(key)

    live_ok = (live == expected_val)
    disk_ok = (persisted == expected_val)

    if live_ok and disk_ok:
        return {"cis_id": cis_id, "title": title, "status": "PASS",
                "message": f"{key} = {expected_val} (live + persistent)", "vulnerability": vulnerability, "tier": tier}
    else:
        msgs = []
        if not live_ok:
            msgs.append(f"Live value: {key} = {live!r} (expected {expected_val!r})")
        if not disk_ok:
            msgs.append(f"Not persisted in sysctl.d (found: {persisted!r})")
        return {"cis_id": cis_id, "title": title, "status": "FAIL",
                "message": "; ".join(msgs), "vulnerability": vulnerability, "tier": tier}


def audit_process_hardening(disk_config, limits_lines):
    """CIS #53–57: ASLR, ptrace, suid_dumpable, core dumps, prelink."""
    results = []

    # #53 · 1.5.1 · ASLR
    results.append(_sysctl_check(
        "1.5.1", "Ensure ASLR is enabled (kernel.randomize_va_space = 2)",
        "kernel.randomize_va_space", "2", disk_config, tier=2,
        vulnerability="Without ASLR, buffer overflow exploits use deterministic memory addresses."
    ))

    # #54 · 1.5.2 · ptrace scope
    results.append(_sysctl_check(
        "1.5.2", "Ensure ptrace is restricted (kernel.yama.ptrace_scope = 1)",
        "kernel.yama.ptrace_scope", "1", disk_config, tier=2,
        vulnerability="Unrestricted ptrace lets any process inject code into another — classic debugger-based attack."
    ))

    # #55 · 1.5.3 · SUID dumpable
    results.append(_sysctl_check(
        "1.5.3", "Ensure SUID core dumps are disabled (fs.suid_dumpable = 0)",
        "fs.suid_dumpable", "0", disk_config, tier=2,
        vulnerability="SUID core dumps can leak credentials and private keys from privileged process memory."
    ))

    # #56 · 1.5.4 · Hard core limit
    hard_core_set = any('hard' in l and 'core' in l and '0' in l for l in limits_lines)
    if hard_core_set:
        results.append({"cis_id": "1.5.4", "title": "Ensure core dump hard limit is 0",
                        "status": "PASS", "message": "* hard core 0 found in limits config",
                        "vulnerability": "Unlimited core dumps are a side-channel for extracting secrets.", "tier": 2})
    else:
        results.append({"cis_id": "1.5.4", "title": "Ensure core dump hard limit is 0",
                        "status": "FAIL", "message": "'* hard core 0' not found in /etc/security/limits.conf or limits.d/",
                        "vulnerability": "Unlimited core dumps are a side-channel for extracting secrets.", "tier": 2})

    # #57 · 1.5.5 · prelink not installed
    prelink_installed = is_package_installed('prelink')
    results.append({
        "cis_id": "1.5.5", "title": "Ensure prelink is not installed",
        "status": "FAIL" if prelink_installed else "PASS",
        "message": "prelink IS installed — undermines ASLR" if prelink_installed else "prelink is not installed",
        "vulnerability": "prelink modifies binary offsets, making ASLR offsets predictable and bypassing exploit mitigations.",
        "tier": 2
    })

    return results


def audit_ipv4_network_parameters(disk_config):
    """CIS #58–66: IPv4 forwarding, redirects, martians, syncookies, rp_filter, ICMP."""
    results = []

    checks = [
        ("3.3.1.1",  "Ensure IP forwarding is disabled",
         "net.ipv4.ip_forward", "0",
         "A forwarding laptop acts as a router, creating unintended network transit paths."),
        ("3.3.1.4",  "Ensure send_redirects (all) is disabled",
         "net.ipv4.conf.all.send_redirects", "0",
         "Sending ICMP redirects can misdirect other hosts' routing — MITM setup step."),
        ("3.3.1.5",  "Ensure send_redirects (default) is disabled",
         "net.ipv4.conf.default.send_redirects", "0",
         "Sending ICMP redirects can misdirect other hosts' routing — MITM setup step."),
        ("3.3.1.8",  "Ensure accept_redirects (all) is disabled",
         "net.ipv4.conf.all.accept_redirects", "0",
         "Accepting ICMP redirects lets an attacker silently reroute traffic."),
        ("3.3.1.9",  "Ensure accept_redirects (default) is disabled",
         "net.ipv4.conf.default.accept_redirects", "0",
         "Accepting ICMP redirects lets an attacker silently reroute traffic."),
        ("3.3.1.10", "Ensure secure_redirects (all) is disabled",
         "net.ipv4.conf.all.secure_redirects", "0",
         "Even gateway-sourced redirects can be malicious if the gateway is compromised."),
        ("3.3.1.10b", "Ensure secure_redirects (default) is disabled",
         "net.ipv4.conf.default.secure_redirects", "0",
         "Even gateway-sourced redirects can be malicious if the gateway is compromised."),
        ("3.3.1.14", "Ensure source routing is disabled (all)",
         "net.ipv4.conf.all.accept_source_route", "0",
         "Source routing allows senders to bypass firewalls by specifying packet paths."),
         ("3.3.1.14b", "Ensure source routing is disabled (default)",
          "net.ipv4.conf.default.accept_source_route", "0",
          "Source routing allows senders to bypass firewalls by specifying packet paths."),
        ("3.3.1.16", "Ensure martian packet logging is enabled",
         "net.ipv4.conf.all.log_martians", "1",
         "Martian packets reveal IP spoofing or severe network misconfiguration."),
        ("3.3.1.18", "Ensure TCP SYN cookies are enabled",
         "net.ipv4.tcp_syncookies", "1",
         "Without SYN cookies, a SYN flood can exhaust the connection table (DoS)."),
        ("3.3.1.12", "Ensure rp_filter (all) is enabled",
         "net.ipv4.conf.all.rp_filter", "1",
         "Without reverse path filtering, spoofed-source packets are accepted."),
        ("3.3.1.12b","Ensure rp_filter (default) is enabled",
         "net.ipv4.conf.default.rp_filter", "1",
         "Without reverse path filtering on default, spoofed packets pass on new interfaces."),
        ("3.3.1.6",  "Ensure bogus ICMP error responses are ignored",
         "net.ipv4.icmp_ignore_bogus_error_responses", "1",
         "Bogus ICMP errors are used in DoS amplification attacks."),
        ("3.3.1.7",  "Ensure broadcast ICMP requests are ignored",
         "net.ipv4.icmp_echo_ignore_broadcasts", "1",
         "Responding to broadcast ICMP is the basis of Smurf DoS amplification attacks."),
    ]

    for cis_id, title, key, expected, vuln in checks:
        results.append(_sysctl_check(cis_id, title, key, expected, disk_config, tier=2, vulnerability=vuln))

    return results


def audit_ipv6_network_parameters(disk_config):
    """CIS #67–68: IPv6 redirects and Router Advertisements."""
    results = []

    # #67 · 3.3.2.3 · IPv6 accept_redirects
    results.append(_sysctl_check(
        "3.3.2.3", "Ensure IPv6 accept_redirects (all) is disabled",
        "net.ipv6.conf.all.accept_redirects", "0", disk_config, tier=2,
        vulnerability="IPv6 ICMP redirect attacks carry the same MITM risk as IPv4 but are often overlooked."
    ))
    results.append(_sysctl_check(
        "3.3.2.3b", "Ensure IPv6 accept_redirects (default) is disabled",
        "net.ipv6.conf.default.accept_redirects", "0", disk_config, tier=2,
        vulnerability="IPv6 ICMP redirect attacks carry the same MITM risk as IPv4 but are often overlooked."
    ))

    # #68 · 3.3.2.7 · IPv6 Router Advertisements (⚠ SLAAC caveat)
    live_all = get_live_sysctl("net.ipv6.conf.all.accept_ra")
    live_def = get_live_sysctl("net.ipv6.conf.default.accept_ra")
    disk_all = disk_config.get("net.ipv6.conf.all.accept_ra")
    disk_def = disk_config.get("net.ipv6.conf.default.accept_ra")

    if live_all == "0" and live_def == "0" and disk_all == "0" and disk_def == "0":
        results.append({"cis_id": "3.3.2.7", "title": "Ensure IPv6 Router Advertisements are rejected",
                        "status": "PASS", "message": "accept_ra = 0 (live + persistent) for all and default",
                        "vulnerability": "A rogue RA can silently replace the default IPv6 gateway and redirect all traffic.",
                        "tier": 2})
    else:
        results.append({"cis_id": "3.3.2.7",
                        "title": "Ensure IPv6 Router Advertisements are rejected",
                        "status": "FAIL",
                        "message": (f"accept_ra live: all={live_all}, default={live_def}; "
                                    f"persisted: all={disk_all}, default={disk_def}. "
                                    "⚠ Verify with 'ip -6 route' before applying if using IPv6 SLAAC."),
                        "vulnerability": "A rogue RA can silently replace the default IPv6 gateway and redirect all traffic.",
                        "tier": 2})

    return results


def audit_kernel_module_blacklisting(modprobe_lines):
    """CIS #69–71: DCCP, TIPC, SCTP module blacklisting."""
    results = []

    modules = [
        ("3.2.1", "dccp", "DCCP has known kernel-level vulnerabilities and is never used in practice."),
        ("3.2.2", "tipc", "TIPC is a cluster protocol with no workstation use and known CVEs."),
        ("3.2.4", "sctp", "SCTP is rarely needed on workstations and has privilege escalation CVEs."),
    ]

    for cis_id, mod, vuln in modules:
        has_install  = any(f"install {mod} /bin/false" in l for l in modprobe_lines)
        has_blacklist = any(f"blacklist {mod}" in l for l in modprobe_lines)

        # Also check if the module is currently loaded
        try:
            lsmod = subprocess.run(['lsmod'], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
            is_loaded = mod in lsmod.stdout
        except Exception:
            is_loaded = False

        if has_install and has_blacklist and not is_loaded:
            results.append({"cis_id": cis_id,
                            "title": f"Ensure {mod.upper()} kernel module is blacklisted",
                            "status": "PASS",
                            "message": f"{mod} is blacklisted (install + blacklist) and not currently loaded.",
                            "vulnerability": vuln, "tier": 2})
        else:
            msgs = []
            if not has_install:
                msgs.append(f"'install {mod} /bin/false' not found in modprobe.d")
            if not has_blacklist:
                msgs.append(f"'blacklist {mod}' not found in modprobe.d")
            if is_loaded:
                msgs.append(f"{mod} module is currently LOADED in the kernel")
            results.append({"cis_id": cis_id,
                            "title": f"Ensure {mod.upper()} kernel module is blacklisted",
                            "status": "FAIL", "message": "; ".join(msgs),
                            "vulnerability": vuln, "tier": 2})

    return results


def audit_bootloader_and_mac():
    """CIS #72–75: GRUB permissions, AppArmor installed/active/enforced."""
    results = []

    # #72 · 1.4.2 · GRUB config permissions
    grub_path = "/boot/grub/grub.cfg"
    if os.path.isfile(grub_path):
        st = os.stat(grub_path)
        mode = oct(st.st_mode)[-4:]  # e.g. '0600'
        mode_int = st.st_mode & 0o777
        owner_uid = st.st_uid
        owner_gid = st.st_gid
        # Must be owned root:root and not world-readable (mode 400 or 600 max)
        world_readable = bool(mode_int & 0o004)
        world_writable  = bool(mode_int & 0o002)
        if owner_uid == 0 and owner_gid == 0 and not world_readable and not world_writable:
            results.append({"cis_id": "1.4.2", "title": "Ensure GRUB config permissions are secure",
                            "status": "PASS", "message": f"{grub_path}: mode {mode}, owned root:root",
                            "vulnerability": "World-readable GRUB config reveals kernel params; writable allows boot-time backdoors.",
                            "tier": 1})
        else:
            results.append({"cis_id": "1.4.2", "title": "Ensure GRUB config permissions are secure",
                            "status": "FAIL",
                            "message": (f"{grub_path}: mode {mode}, uid={owner_uid}, gid={owner_gid}. "
                                        "Expected: mode 400 or 600, owned root:root, not world-readable."),
                            "vulnerability": "World-readable GRUB config reveals kernel params; writable allows boot-time backdoors.",
                            "tier": 1})
    else:
        results.append({"cis_id": "1.4.2", "title": "Ensure GRUB config permissions are secure",
                        "status": "N/A", "message": f"{grub_path} not found (EFI system or non-standard GRUB path)",
                        "vulnerability": "World-readable GRUB config reveals kernel params.", "tier": 1})

    # #73 · 1.3.1.1 · AppArmor packages installed and service active
    aa_installed    = is_package_installed('apparmor')
    aautils_installed = is_package_installed('apparmor-utils')
    aa_active       = check_service_active('apparmor')

    if aa_installed and aautils_installed and aa_active:
        results.append({"cis_id": "1.3.1.1", "title": "Ensure AppArmor is installed and active",
                        "status": "PASS", "message": "apparmor + apparmor-utils installed; service is active",
                        "vulnerability": "Without AppArmor, all processes run with unrestricted OS permissions.",
                        "tier": 1})
    else:
        msgs = []
        if not aa_installed:      msgs.append("apparmor package NOT installed")
        if not aautils_installed: msgs.append("apparmor-utils package NOT installed")
        if not aa_active:         msgs.append("apparmor service is NOT active")
        results.append({"cis_id": "1.3.1.1", "title": "Ensure AppArmor is installed and active",
                        "status": "FAIL", "message": "; ".join(msgs),
                        "vulnerability": "Without AppArmor, all processes run with unrestricted OS permissions.",
                        "tier": 1})

    # #74 · 1.3.1.3 · No profiles in 'disabled' state
    disabled_dir = "/etc/apparmor.d/disable"
    disabled_profiles = []
    if os.path.isdir(disabled_dir):
        disabled_profiles = [f for f in os.listdir(disabled_dir)
                             if os.path.isfile(os.path.join(disabled_dir, f))]

    if not disabled_profiles:
        results.append({"cis_id": "1.3.1.3", "title": "Ensure no AppArmor profiles are in disabled state",
                        "status": "PASS", "message": "No profiles found in /etc/apparmor.d/disable/",
                        "vulnerability": "A disabled AppArmor profile provides zero protection — same as having no AppArmor.",
                        "tier": 1})
    else:
        results.append({"cis_id": "1.3.1.3", "title": "Ensure no AppArmor profiles are in disabled state",
                        "status": "FAIL",
                        "message": f"{len(disabled_profiles)} profile(s) are disabled: {', '.join(disabled_profiles[:5])}",
                        "vulnerability": "A disabled AppArmor profile provides zero protection — same as having no AppArmor.",
                        "tier": 1})

    # #75 · 1.3.1.4 · All profiles in 'enforce' mode (L2)
    try:
        aa_status = subprocess.run(
            ['aa-status', '--json'],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True
        )
        if aa_status.returncode == 0:
            aa_data = json.loads(aa_status.stdout)
            complain_count = len(aa_data.get('profiles', {}).get('complain', []))
            enforce_count  = len(aa_data.get('profiles', {}).get('enforce', []))
        else:
            # Fallback: parse text output
            aa_text = subprocess.run(
                ['aa-status'],
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True
            ).stdout
            complain_count = 0
            enforce_count  = 0
            for line in aa_text.splitlines():
                if 'complain mode' in line:
                    try: complain_count = int(line.split()[0])
                    except: pass
                if 'enforce mode' in line:
                    try: enforce_count = int(line.split()[0])
                    except: pass

        if complain_count == 0:
            results.append({"cis_id": "1.3.1.4",
                            "title": "Ensure all AppArmor profiles are in enforce mode",
                            "status": "PASS",
                            "message": f"0 profiles in complain mode; {enforce_count} in enforce mode",
                            "vulnerability": "Complain mode only logs violations — it does NOT block anything.",
                            "tier": 3})
        else:
            results.append({"cis_id": "1.3.1.4",
                            "title": "Ensure all AppArmor profiles are in enforce mode",
                            "status": "FAIL",
                            "message": f"{complain_count} profile(s) in complain mode (not blocking). Run: aa-enforce /etc/apparmor.d/*",
                            "vulnerability": "Complain mode only logs violations — it does NOT block anything.",
                            "tier": 3})
    except Exception as e:
        results.append({"cis_id": "1.3.1.4",
                        "title": "Ensure all AppArmor profiles are in enforce mode",
                        "status": "FAIL",
                        "message": f"Could not run aa-status: {e}",
                        "vulnerability": "Complain mode only logs violations — it does NOT block anything.",
                        "tier": 3})

    return results


# ==========================================
# 3. ORCHESTRATION & REPORTING ENGINE
# ==========================================
def main():
    all_results = []

    # 1. Load all data sources into memory once
    disk_config    = get_disk_sysctl_config()
    modprobe_lines = get_modprobe_config()
    limits_lines   = get_limits_config()

    # 2. Execute all audit groups
    all_results.extend(audit_process_hardening(disk_config, limits_lines))
    all_results.extend(audit_ipv4_network_parameters(disk_config))
    all_results.extend(audit_ipv6_network_parameters(disk_config))
    all_results.extend(audit_kernel_module_blacklisting(modprobe_lines))
    all_results.extend(audit_bootloader_and_mac())

    # 3. Segregate results
    passed_or_na = [r for r in all_results if r['status'] in ('PASS', 'N/A')]
    failed       = [r for r in all_results if r['status'] == 'FAIL']
    failed.sort(key=lambda x: x.get('tier', 1))

    # 4. Build JSON report
    report_data = {
        "module": "Module 3 — Kernel & Network Stack Hardening",
        "total_checks": len(all_results),
        "passed_or_na": len(passed_or_na),
        "failed": len(failed),
        "compliant_and_na_checks": [f"{r['cis_id']} ({r['status']})" for r in passed_or_na],
        "failures_by_tier": {"tier_1": [], "tier_2": [], "tier_3": []}
    }

    for item in failed:
        tier_key = f"tier_{item.get('tier', 1)}"
        report_data["failures_by_tier"][tier_key].append({
            "cis_id":        item['cis_id'],
            "title":         item['title'],
            "message":       item['message'],
            "vulnerability": item['vulnerability']
        })

    # Remove empty tier buckets
    report_data["failures_by_tier"] = {
        k: v for k, v in report_data["failures_by_tier"].items() if v
    }
    # 5. Output JSON Report
    output_file = "module3_report.json"
    with open(output_file, "w") as f:
        json.dump(report_data, f, indent=4)

    print(f"\n✅ Module 3 audit complete! {len(passed_or_na)} passed/N/A, {len(failed)} failed.")
    print(f"   Results written to: {os.path.abspath(output_file)}")

if __name__ == "__main__":
    main()