#!/usr/bin/env python3


import os
import sys
import json
import glob
import re
import subprocess

# ══════════════════════════════════════════════════════════════════════════════
# 0. EXECUTION CONTEXT VERIFICATION
# ══════════════════════════════════════════════════════════════════════════════

if os.geteuid() != 0:
    print("FATAL: This script must be executed as root  →  sudo python3 module5_server.py")
    sys.exit(1)


# ══════════════════════════════════════════════════════════════════════════════
# 1. SHARED HELPERS & PARSERS
# ══════════════════════════════════════════════════════════════════════════════

def _run(cmd: list, timeout: int = 20) -> tuple:
    """
    Single subprocess gateway — no shell=True, no sudo embedded.
    Returns (returncode, stdout_str, stderr_str). Never raises.
    """
    try:
        r = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
        )
        return r.returncode, r.stdout.strip(), r.stderr.strip()
    except FileNotFoundError:
        return 127, "", f"command not found: {cmd[0]}"
    except subprocess.TimeoutExpired:
        return 1, "", f"timed out ({timeout}s): {' '.join(cmd)}"


def _pkg_installed(pkg: str) -> bool:
    rc, out, _ = _run(["dpkg-query", "-W", "-f=${Status}", pkg])
    return rc == 0 and "install ok installed" in out


def _svc_active(unit: str) -> bool:
    """True when systemctl is-active returns 'active'."""
    _, out, _ = _run(["systemctl", "is-active", unit])
    return out == "active"


def _svc_enabled(unit: str) -> bool:
    _, out, _ = _run(["systemctl", "is-enabled", unit])
    return out.startswith("enabled")


def _get_modprobe_showconfig() -> str:
    """
    modprobe --showconfig aggregates all /etc/modprobe.d/*.conf entries
    into one normalised stream — authoritative source for install + blacklist checks.
    Called once per group that needs it; callers cache the result.
    """
    _, out, _ = _run(["modprobe", "--showconfig"])
    return out


def _get_lsmod() -> str:
    """lsmod output — called once; callers cache the result."""
    _, out, _ = _run(["lsmod"])
    return out


def _findmnt_opts(path: str) -> str:
    """
    findmnt -kn <path>: returns the mount-info line or '' if not a
    separate mountpoint.  -k = kernel filesystems, -n = no header.
    """
    _, out, _ = _run(["findmnt", "-kn", "-o", "OPTIONS", path])
    return out.strip()


def _result(cis_id, title, status, message, vulnerability, tier) -> dict:
    """Canonical result dict matching the module4 schema."""
    return {
        "cis_id":        cis_id,
        "title":         title,
        "status":        status,          # "PASS" | "FAIL" | "N/A"
        "message":       message,
        "vulnerability": vulnerability,
        "tier":          tier,            # 1 | 2 | 3
    }


# ══════════════════════════════════════════════════════════════════════════════
# 2. AUDIT GROUPS
# ══════════════════════════════════════════════════════════════════════════════

# ── GROUP A ──────────────────────────────────────────────────────────────────
def audit_wireless() -> list:
    """
    S-1 | CIS 3.1.2 | L1-Server only | T1

    CIS bash audit (PDF p.333-334) translated to Python:
      Source of truth: /sys/class/net/*/wireless  (sysfs, not ifconfig/ip)
      For every wireless NIC found, resolve its kernel module via:
        readlink -f <nic>/device/driver/module  → basename = module name
      Per-module checks (3 conditions, all must be true for PASS):
        (a) modprobe -n -v <mod>  must contain 'install /bin/false|true'
            → means the module is blocked from loading
        (b) lsmod                 must NOT list the module
            → means not currently loaded
        (c) modprobe --showconfig must contain 'blacklist <mod>'
            → means it's on the persistent deny-list

    N/A when: /sys/class/net has no 'wireless' sub-directory at all.
              (server has no wireless hardware — trivial pass per CIS)
    """
    CIS_ID = "3.1.2"
    TITLE  = "Ensure wireless interfaces are not available"
    VULN   = ("An active wireless interface on a server creates an unintended RF "
              "attack surface. Wireless kernel drivers have a long CVE history "
              "including remote code execution. Servers live on wired LANs — "
              "wireless hardware must be disabled at the kernel module level.")

    # Discover wireless NICs via sysfs (same approach as CIS bash script)
    wireless_sysfs = glob.glob("/sys/class/net/*/wireless")

    if not wireless_sysfs:
        return [_result(CIS_ID, TITLE, "N/A",
                        "No /sys/class/net/*/wireless entries found. "
                        "This system has no wireless hardware — check passes trivially.",
                        VULN, 1)]

    # Resolve kernel module name for each NIC
    # Path: /sys/class/net/<iface>/wireless -> parent dir -> device/driver/module symlink
    module_names = set()
    for wdir in wireless_sysfs:
        nic_dir  = os.path.dirname(wdir)                          # /sys/class/net/<iface>
        mod_link = os.path.join(nic_dir, "device", "driver", "module")
        try:
            resolved = os.path.realpath(mod_link)
            module_names.add(os.path.basename(resolved))
        except (OSError, ValueError):
            pass

    if not module_names:
        return [_result(CIS_ID, TITLE, "N/A",
                        "Wireless sysfs entries exist but driver module symlinks "
                        "could not be resolved. Inspect /sys/class/net/*/wireless manually.",
                        VULN, 1)]

    # Fetch shared sources once
    showconfig = _get_modprobe_showconfig()
    lsmod_out  = _get_lsmod()

    per_module_fails  = []
    per_module_passes = []

    for mod in sorted(module_names):

        issues = []

        # (a) loadability: modprobe -n -v <mod>
        _, loadable_out, _ = _run(["modprobe", "-n", "-v", mod])
        not_loadable = bool(
            re.search(r"^\s*install\s+/bin/(true|false)\b", loadable_out, re.MULTILINE)
        )
        if not not_loadable:
            issues.append("not install-denied (modprobe -n -v shows no /bin/false entry)")

        # (b) currently loaded: lsmod
        # lsmod uses underscores; module names from sysfs may use hyphens
        mod_key = mod.replace("-", "_")
        is_loaded = bool(
            re.search(rf"^{re.escape(mod_key)}\b", lsmod_out, re.MULTILINE)
        )
        if is_loaded:
            issues.append("currently loaded in kernel (lsmod)")

        # (c) deny-listed: modprobe --showconfig
        mod_key = mod.replace("-", "_")
        is_denylisted = bool(
            re.search(rf"^\s*blacklist\s+{re.escape(mod_key)}\b",
                      showconfig, re.MULTILINE)
        )
        if not is_denylisted:
            issues.append("not deny-listed in modprobe config")

        if issues:
            per_module_fails.append(f"  module '{mod}': {'; '.join(issues)}")
        else:
            per_module_passes.append(mod)

    if per_module_fails:
        return [_result(CIS_ID, TITLE, "FAIL",
                        "Wireless module(s) failed checks:\n" +
                        "\n".join(per_module_fails),
                        VULN, 1)]

    return [_result(CIS_ID, TITLE, "PASS",
                    f"All wireless module(s) ({', '.join(sorted(module_names))}) "
                    "are install-denied, not loaded, and deny-listed.",
                    VULN, 1)]


# ── GROUP B ──────────────────────────────────────────────────────────────────
def audit_gui_stack() -> list:
    """
    S-2 | CIS 2.1.20 | L2-Server only | T3
    S-3 | CIS 1.7.1  | L2-Server only | T3

    Grouped: both audit the GUI stack with identical dpkg-query pattern.
    Two separate result dicts returned (different CIS IDs / titles).

    CIS audit (PDF p.183 & p.261):
      2.1.20: dpkg-query -s xserver-common  → nothing returned = PASS
      1.7.1:  dpkg-query -s gdm3            → nothing returned = PASS

    Additional defence-in-depth: check display manager services aren't
    active/enabled even if package was removed but unit files linger.
    """
    results = []

    # ── S-2: 2.1.20 X window server ───────────────────────────────────────
    VULN_X = ("An X server on a headless server exposes the X11 display protocol "
              "stack with no operational justification, adding thousands of "
              "CVE-exposed lines and enabling remote session hijacking via X11.")

    x_installed = _pkg_installed("xserver-common")

    # Display managers that imply an X stack even without xserver-common
    dm_units = ["xdm.service", "gdm3.service", "lightdm.service", "sddm.service"]
    active_dms  = [u for u in dm_units if _svc_active(u)]
    enabled_dms = [u for u in dm_units if _svc_enabled(u)]

    x_fails = []
    if x_installed:
        x_fails.append("package 'xserver-common' is installed")
    if active_dms:
        x_fails.append(f"display manager unit(s) active: {', '.join(active_dms)}")
    if enabled_dms:
        x_fails.append(f"display manager unit(s) enabled: {', '.join(enabled_dms)}")

    if x_fails:
        results.append(_result(
            "2.1.20",
            "Ensure X window server services are not in use",
            "FAIL",
            " | ".join(x_fails),
            VULN_X, 3))
    else:
        results.append(_result(
            "2.1.20",
            "Ensure X window server services are not in use",
            "PASS",
            "Package 'xserver-common' is not installed. "
            "No display manager service is active or enabled.",
            VULN_X, 3))

    # ── S-3: 1.7.1 GDM removed ────────────────────────────────────────────
    VULN_G = ("GDM on a server means a full GNOME GUI stack is installed with no "
              "operational need. On server CIS 1.7.1 requires removal; "
              "on workstation CIS 1.7.2-1.7.10 requires configuration — "
              "these profiles are mutually exclusive.")

    if _pkg_installed("gdm3"):
        results.append(_result(
            "1.7.1",
            "Ensure GDM is removed",
            "FAIL",
            "Package 'gdm3' is installed. Expected: not installed on a server.",
            VULN_G, 3))
    else:
        results.append(_result(
            "1.7.1",
            "Ensure GDM is removed",
            "PASS",
            "Package 'gdm3' is not installed.",
            VULN_G, 3))

    return results


# ── GROUP C ──────────────────────────────────────────────────────────────────
def audit_kernel_modules() -> list:
    """
    S-4 | CIS 1.1.1.9 | L1-Server | T1
    usb-storage kernel module must not be available, loaded, or loadable.

    CIS audit (PDF p.47-48) — three-step check:
      Step 1: Does the module directory exist under /lib/modules/<uname-r>/?
              If absent → N/A (module not compiled for this kernel — trivial pass)
      Step 2: lsmod | grep usb.storage  → nothing (not currently loaded)
      Step 3: modprobe --showconfig must show BOTH:
                blacklist usb_storage
                install usb_storage /bin/false   (or /bin/true)

    Note: CIS bash normalises 'usb-storage' / 'usb_storage' interchangeably.
          modprobe showconfig always uses underscores; lsmod always uses underscores.
    """
    CIS_ID = "1.1.1.9"
    TITLE  = "Ensure usb-storage kernel module is not available"
    VULN   = ("USB storage is the most common physical vector for introducing "
              "malware and exfiltrating data from servers. No USB mass-storage "
              "use case exists in a datacenter environment.")

    # Step 1 — module directory existence
    _, uname_out, _ = _run(["uname", "-r"])
    kernel_ver = uname_out

    candidate_paths = [
        f"/lib/modules/{kernel_ver}/kernel/drivers/usb/storage",
        f"/usr/lib/modules/{kernel_ver}/kernel/drivers/usb/storage",
    ]
    mod_dir_exists = any(
        os.path.isdir(p) and os.listdir(p) for p in candidate_paths
    )

    if not mod_dir_exists:
        return [_result(CIS_ID, TITLE, "N/A",
                        f"usb-storage module directory absent under "
                        f"/lib/modules/{kernel_ver}/kernel/drivers/usb/storage. "
                        "Module not compiled for this kernel — trivial pass.",
                        VULN, 1)]

    # Steps 2 & 3 — fetch shared sources once
    showconfig = _get_modprobe_showconfig()
    lsmod_out  = _get_lsmod()

    fails = []

    # Step 2: currently loaded?
    if re.search(r"^usb_storage\b", lsmod_out, re.MULTILINE):
        fails.append("module usb_storage is currently loaded (lsmod)")

    # Step 3a: install deny
    if not re.search(r"^\s*install\s+usb_storage\s+/bin/(false|true)\b",
                     showconfig, re.MULTILINE):
        fails.append("'install usb_storage /bin/false' not found in modprobe config")

    # Step 3b: blacklist
    if not re.search(r"^\s*blacklist\s+usb_storage\b", showconfig, re.MULTILINE):
        fails.append("'blacklist usb_storage' not found in modprobe config")

    if fails:
        return [_result(CIS_ID, TITLE, "FAIL", " | ".join(fails), VULN, 1)]

    return [_result(CIS_ID, TITLE, "PASS",
                    "usb-storage module exists on this kernel but is not loaded, "
                    "is install-denied, and is blacklisted in modprobe config.",
                    VULN, 1)]


# ── GROUP D ──────────────────────────────────────────────────────────────────

# Table-driven service definitions — (cis_id, title, tier, package, socket_units, svc_units, vuln)
# CIS audit pattern for all three (PDF p.211-238):
#   Preferred: dpkg-query -s <pkg> → nothing returned
#   Fallback (if pkg required as dependency):
#     systemctl is-enabled <units> | grep 'enabled' → nothing
#     systemctl is-active  <units> | grep '^active' → nothing
_SERVICE_TABLE = [
    (
        "2.1.1",
        "Ensure autofs services are not in use",
        1,
        "autofs",
        [],
        ["autofs.service"],
        ("Automounting on a server lets anyone with physical access introduce "
         "unauthorised USB or optical media directly into the filesystem "
         "without administrator credentials."),
    ),
    (
        "2.1.2",
        "Ensure avahi daemon services are not in use",
        1,
        "avahi-daemon",
        ["avahi-daemon.socket"],
        ["avahi-daemon.service"],
        ("Avahi broadcasts mDNS/DNS-SD service discovery on the local network, "
         "leaking server topology and providing an unauthenticated protocol "
         "surface with zero server-side use case."),
    ),
    (
        "2.1.11",
        "Ensure print server services are not in use",
        1,
        "cups",
        ["cups.socket"],
        ["cups.service"],
        ("CUPS on a server has no purpose. Its built-in web admin interface "
         "on port 631 needlessly expands the network attack surface."),
    ),
]


def audit_services() -> list:
    """
    S-5 | CIS 2.1.1  autofs       | L1-Server | T1
    S-6 | CIS 2.1.2  avahi-daemon | L1-Server | T1
    S-7 | CIS 2.1.11 cups         | L1-Server | T1

    All three share the same CIS audit pattern; driven by _SERVICE_TABLE above.
    Returns one result dict per service.
    """
    results = []

    for (cis_id, title, tier, pkg, sockets, services, vuln) in _SERVICE_TABLE:

        pkg_present = _pkg_installed(pkg)

        all_units     = sockets + services
        active_units  = [u for u in all_units if _svc_active(u)]
        enabled_units = [u for u in all_units if _svc_enabled(u)]

        fails = []
        if pkg_present:
            fails.append(f"package '{pkg}' is installed")
        if active_units:
            fails.append(f"unit(s) active: {', '.join(active_units)}")
        if enabled_units:
            fails.append(f"unit(s) enabled: {', '.join(enabled_units)}")

        if fails:
            results.append(_result(cis_id, title, "FAIL",
                                   " | ".join(fails), vuln, tier))
        else:
            results.append(_result(cis_id, title, "PASS",
                                   f"Package '{pkg}' is not installed and "
                                   "no associated units are active or enabled.",
                                   vuln, tier))

    return results


# ── GROUP E ──────────────────────────────────────────────────────────────────

def _check_mount_opts(mountpoint: str, options: list,
                      cis_id: str, title: str, tier: int, vuln: str) -> dict:
    """
    Shared helper for all mount-option checks (S-9, S-10, S-12, S-14, S-16).

    CIS audit pattern (PDF p.90-120):
      findmnt -kn <path>  → if empty: mountpoint is not separate → N/A
                          → if present: parse options field, verify each opt present

    findmnt -kn output columns (no header, kernel filesystems only):
      TARGET  SOURCE  FSTYPE  OPTIONS
    OPTIONS is always the 4th whitespace-separated token and is comma-delimited.

    Pre-condition handled here: if findmnt returns nothing the partition is not
    separate — we return N/A, not FAIL (manual partition check is S-8/11/13/15).
    """
    options_field = _findmnt_opts(mountpoint)

    if not options_field:
        return _result(
            cis_id, title, "N/A",
            f"'{mountpoint}' is not a separate mountpoint (findmnt -kn returned empty). "
            "Mount-option check skipped — resolve the corresponding partition check first.",
            vuln, tier)

    # Parse OPTIONS field (index 3) from findmnt output
    # findmnt -kn may wrap long lines; take the last line to be safe
    last_line    = options_field.splitlines()[-1]
    fields       = last_line.split()
    options_field = fields[3] if len(fields) >= 4 else ""
    active_opts  = set(options_field.split(","))

    missing = [opt for opt in options if opt not in active_opts]

    if missing:
        return _result(cis_id, title, "FAIL",
                       f"Missing mount option(s) on {mountpoint}: "
                       f"{', '.join(missing)}. "
                       f"Current options: {options_field}",
                       vuln, tier)

    return _result(cis_id, title, "PASS",
                   f"All required option(s) ({', '.join(options)}) present on "
                   f"{mountpoint}. Options: {options_field}",
                   vuln, tier)


def audit_var_mount_options() -> list:
    """
    S-9  | CIS 1.1.2.4.2   /var           nodev              | L1-S+W | T1
    S-10 | CIS 1.1.2.4.3   /var           nosuid             | L1-S+W | T1
    S-12 | CIS 1.1.2.5.2-4 /var/tmp       nodev+nosuid+noexec| L1-S+W | T1
    S-14 | CIS 1.1.2.6.2-4 /var/log       nodev+nosuid+noexec| L1-S+W | T1
    S-16 | CIS 1.1.2.7.2-4 /var/log/audit nodev+nosuid+noexec| L1-S+W | T1

    Each grouped option-set (S-12, S-14, S-16) collapses three sequential CIS
    rules into one check against one findmnt call — same remediation, same target.
    """
    results = []

    # /var — nodev (S-9) and nosuid (S-10) are separate CIS IDs, separate results
    results.append(_check_mount_opts(
        mountpoint="/var",
        options=["nodev"],
        cis_id="1.1.2.4.2",
        title="Ensure nodev option set on /var partition",
        tier=1,
        vuln=("nodev on /var prevents creation of block/character device files "
              "in daemon-writable directories, blocking device-based privilege "
              "escalation from world-writable paths inside /var."),
    ))

    results.append(_check_mount_opts(
        mountpoint="/var",
        options=["nosuid"],
        cis_id="1.1.2.4.3",
        title="Ensure nosuid option set on /var partition",
        tier=1,
        vuln=("nosuid on /var prevents SUID binaries staged in daemon-writable "
              "directories from granting elevated privileges when executed — "
              "a common post-compromise lateral movement technique."),
    ))

    # /var/tmp — nodev+nosuid+noexec grouped (S-12)
    results.append(_check_mount_opts(
        mountpoint="/var/tmp",
        options=["nodev", "nosuid", "noexec"],
        cis_id="1.1.2.5.2-4",
        title="Ensure nodev, nosuid, noexec options set on /var/tmp partition",
        tier=1,
        vuln=("/var/tmp is world-writable and persistent across reboots. "
              "Without nodev+nosuid+noexec any local user can plant device files, "
              "SUID binaries, or executable scripts there as an attack staging area."),
    ))

    # /var/log — nodev+nosuid+noexec grouped (S-14)
    results.append(_check_mount_opts(
        mountpoint="/var/log",
        options=["nodev", "nosuid", "noexec"],
        cis_id="1.1.2.6.2-4",
        title="Ensure nodev, nosuid, noexec options set on /var/log partition",
        tier=1,
        vuln=("The log filesystem must never execute code. Without these options "
              "an attacker who gains write access to log directories can plant "
              "and execute malicious code or SUID binaries under /var/log."),
    ))

    # /var/log/audit — nodev+nosuid+noexec grouped (S-16)
    results.append(_check_mount_opts(
        mountpoint="/var/log/audit",
        options=["nodev", "nosuid", "noexec"],
        cis_id="1.1.2.7.2-4",
        title="Ensure nodev, nosuid, noexec options set on /var/log/audit partition",
        tier=1,
        vuln=("The audit log partition must be execution-proof. An attacker who "
              "gains write access to /var/log/audit could otherwise plant and "
              "execute code or escalate privileges through the audit log path."),
    ))

    return results


# ══════════════════════════════════════════════════════════════════════════════
# 3. ORCHESTRATION & REPORTING ENGINE
#    Structure kept verbatim from module4.py skeleton — only names/paths changed.
# ══════════════════════════════════════════════════════════════════════════════

def main():
    all_results = []

    # 1. Execute audit groups (each group pre-loads its own sources internally)
    all_results.extend(audit_wireless())            # Group A  S-1
    all_results.extend(audit_gui_stack())           # Group B  S-2, S-3
    all_results.extend(audit_kernel_modules())      # Group C  S-4
    all_results.extend(audit_services())            # Group D  S-5, S-6, S-7
    all_results.extend(audit_var_mount_options())   # Group E  S-9, S-10, S-12, S-14, S-16

    # 2. Segregate Results
    passed_or_na = [r for r in all_results if r["status"] in ("PASS", "N/A")]
    failed       = [r for r in all_results if r["status"] == "FAIL"]
    failed.sort(key=lambda x: x.get("tier", 1))

    # 3. Construct JSON Structure
    report_data = {
        "module":          "Module 5 — CIS Ubuntu 22.04 LTS Server-Specific Controls",
        "profile":         "L1-Server & L2-Server",
        "target":          "Ubuntu 22.04.5 LTS Server",
        "benchmark":       "CIS Benchmark v3.0.0 (Oct 2025)",
        "total_checks":    len(all_results),
        "passed_or_na":    len(passed_or_na),
        "failed":          len(failed),
        "compliant_and_na_checks": [
            f"{r['cis_id']} — {r['title']} ({r['status']})" for r in passed_or_na
        ],
        "failures_by_tier": {"tier_1": [], "tier_2": [], "tier_3": []},
    }

    for item in failed:
        tier_key = f"tier_{item.get('tier', 1)}"
        report_data["failures_by_tier"][tier_key].append({
            "cis_id":        item["cis_id"],
            "title":         item["title"],
            "message":       item["message"],
            "vulnerability": item["vulnerability"],
        })

    # Clean up empty tiers
    report_data["failures_by_tier"] = {
        k: v for k, v in report_data["failures_by_tier"].items() if v
    }

    # 4. Output JSON Report
    output_file = "module5_report.json"
    with open(output_file, "w") as f:
        json.dump(report_data, f, indent=4)

    print(f"\n✅ Module 5 audit complete! "
          f"{len(passed_or_na)} passed/N/A, {len(failed)} failed.")
    print(f"   Results written to: {os.path.abspath(output_file)}")


if __name__ == "__main__":
    main()