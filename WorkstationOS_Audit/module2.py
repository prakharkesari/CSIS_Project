#!/usr/bin/env python3
import os
import sys
import glob
import stat
import pwd
import grp
import json
import subprocess

# ==========================================
# 0. EXECUTION CONTEXT VERIFICATION
# ==========================================
if os.geteuid() != 0:
    print("FATAL: This script must be executed as root (sudo python3 module2_filesystem.py)")
    sys.exit(1)

# ==========================================
# 1. NATIVE FILE PARSERS & QUERIES
# ==========================================
def parse_modprobe():
    """Reads all modprobe config files into a dictionary tracking install and blacklist rules."""
    modules = {}
    for conf_file in glob.glob('/etc/modprobe.d/*.conf'):
        try:
            with open(conf_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line.startswith('#') or not line:
                        continue
                    
                    parts = line.split()
                    if len(parts) >= 3 and parts[0] == 'install' and parts[2] == '/bin/false':
                        mod_name = parts[1]
                        if mod_name not in modules:
                            modules[mod_name] = {'install_false': True, 'blacklisted': False}
                        else:
                            modules[mod_name]['install_false'] = True
                            
                    elif len(parts) >= 2 and parts[0] == 'blacklist':
                        mod_name = parts[1]
                        if mod_name not in modules:
                            modules[mod_name] = {'install_false': False, 'blacklisted': True}
                        else:
                            modules[mod_name]['blacklisted'] = True
        except FileNotFoundError:
            continue
    return modules

def parse_fstab():
    """Reads /etc/fstab and returns a list of dictionaries for active mounts."""
    mounts = []
    try:
        with open('/etc/fstab', 'r') as f:
            for line in f:
                line = line.strip()
                if line.startswith('#') or not line:
                    continue
                parts = line.split()
                if len(parts) >= 4:
                    mounts.append({
                        'device': parts[0],
                        'mountpoint': parts[1],
                        'fstype': parts[2],
                        'options': parts[3].split(',')
                    })
    except FileNotFoundError:
        pass
    return mounts

def get_file_stat(filepath):
    """Natively retrieves octal permissions, owner, and group of a file."""
    try:
        file_stat = os.stat(filepath)
        mode = f"{stat.S_IMODE(file_stat.st_mode):04o}"
        owner = pwd.getpwuid(file_stat.st_uid).pw_name
        group = grp.getgrgid(file_stat.st_gid).gr_name
        return {'exists': True, 'mode': mode, 'owner': owner, 'group': group}
    except FileNotFoundError:
        return {'exists': False}

# ==========================================
# 2. AUDIT MODULES (Logic)
# ==========================================

def audit_kernel_modules(modprobe_data):
    """CIS 1.1.1.x: cramfs, hfs, hfsplus, jffs2, udf, firewire-core"""
    results = []

    # Matrix mapping: (CIS_ID, [List of Modules], Tier, Title, Vulnerability)
    # Grouping them like this allows us to handle the hfs/hfsplus cluster natively.
    kernel_checks = [
        ("1.1.1.1", ["cramfs"], 2, "Ensure mounting of cramfs is disabled", 
         "cramfs is never used on modern systems — reducing loadable module attack surface."),
        
        ("1.1.1.3", ["hfs", "hfsplus"], 2, "Ensure mounting of hfs and hfsplus is disabled", 
         "macOS-only filesystems with no legitimate Linux workstation use — historical CVE exposure."),
        
        ("1.1.1.5", ["jffs2"], 2, "Ensure mounting of jffs2 is disabled", 
         "Flash filesystem — unmaintained upstream with known out-of-bounds vulnerabilities."),
        
        ("1.1.1.8", ["udf"], 2, "Ensure mounting of udf is disabled", 
         "UDF has a long CVE history including kernel panics and privilege escalation via malformed images."),
        
        ("1.1.1.11", ["firewire-core"], 2, "Ensure firewire-core module is disabled", 
         "FireWire (IEEE 1394) enables DMA attacks — physical access can read/write all RAM without OS involvement.")
    ]

    for cis_id, modules, tier, title, vulnerability in kernel_checks:
        failed_mods = []
        
        # Check every module required for this specific CIS ID
        for mod in modules:
            # Fetch the parsed state from our memory dictionary (defaults to empty if not found)
            state = modprobe_data.get(mod, {})
            
            # CIS standard requires BOTH install /bin/false AND blacklist
            if not (state.get('install_false') and state.get('blacklisted')):
                failed_mods.append(mod)

        # Append the completely decoupled result to the final report array
        results.append({
            "cis_id": cis_id,
            "title": title,
            "status": "FAIL" if failed_mods else "PASS",
            "message": f"Missing 'install /bin/false' or 'blacklist' for: {failed_mods}" if failed_mods else f"Correctly disabled: {modules}",
            "vulnerability": vulnerability,
            "tier": tier
        })

    return results

def audit_fstab_mounts(fstab_data):
    """CIS 1.1.2.x: /tmp, /dev/shm, /home mounts and options"""
    results = []

    # Helper function to quickly grab a specific mount point from our parsed memory
    def get_mount(path):
        for entry in fstab_data:
            if entry['mountpoint'] == path:
                return entry
        return None

    # ---------------------------------------------------------
    # 1. /tmp Checks (CIS 1.1.2.1.1 and 1.1.2.1.2-4)
    # ---------------------------------------------------------
    tmp_mount = get_mount('/tmp')
    
    # Base check: Does /tmp exist at all?
    results.append({
        "cis_id": "1.1.2.1.1",
        "title": "Ensure /tmp is configured",
        "status": "PASS" if tmp_mount else "FAIL",
        "message": "/tmp is correctly defined in fstab." if tmp_mount else "/tmp is missing from /etc/fstab.",
        "vulnerability": "Keeps /tmp in memory or isolated — prevents /tmp exhaustion from filling the root filesystem.",
        "tier": 1
    })

    # Options check: nodev, nosuid, noexec
    if tmp_mount:
        req_opts = ['nodev', 'nosuid', 'noexec']
        missing = [opt for opt in req_opts if opt not in tmp_mount['options']]
        results.append({
            "cis_id": "1.1.2.1.2-4",
            "title": "Ensure nodev, nosuid, and noexec are set on /tmp",
            "status": "FAIL" if missing else "PASS",
            "message": f"Missing options on /tmp: {missing}" if missing else "/tmp has all required security options.",
            "vulnerability": "nodev prevents device files, nosuid prevents SUID binaries, noexec prevents script execution.",
            "tier": 1
        })
    else:
        # Avoid false positives by marking options check as N/A if /tmp isn't mounted
        results.append({
            "cis_id": "1.1.2.1.2-4", "title": "Ensure nodev, nosuid, and noexec are set on /tmp",
            "status": "N/A", "message": "N/A - /tmp is not defined in fstab.", "vulnerability": "N/A", "tier": 1
        })

    # ---------------------------------------------------------
    # 2. /dev/shm Checks (CIS 1.1.2.2.2-4)
    # ---------------------------------------------------------
    shm_mount = get_mount('/dev/shm')
    if shm_mount:
        req_opts = ['nodev', 'nosuid', 'noexec']
        missing = [opt for opt in req_opts if opt not in shm_mount['options']]
        results.append({
            "cis_id": "1.1.2.2.2-4",
            "title": "Ensure nodev, nosuid, and noexec are set on /dev/shm",
            "status": "FAIL" if missing else "PASS",
            "message": f"Missing options on /dev/shm: {missing}" if missing else "/dev/shm has all required security options.",
            "vulnerability": "Shared memory is a favourite attack staging area — noexec prevents in-memory execution attacks.",
            "tier": 1
        })
    else:
        # /dev/shm is managed by systemd natively. If it's missing from fstab, it lacks 'noexec' by default, so it's a hard fail.
        results.append({
            "cis_id": "1.1.2.2.2-4",
            "title": "Ensure nodev, nosuid, and noexec are set on /dev/shm",
            "status": "FAIL",
            "message": "/dev/shm is not explicitly secured in /etc/fstab.",
            "vulnerability": "Shared memory is a favourite attack staging area — noexec prevents in-memory execution attacks.",
            "tier": 1
        })

    # ---------------------------------------------------------
    # 3. /home Checks (CIS 1.1.2.3.2-3)
    # ---------------------------------------------------------
    home_mount = get_mount('/home')
    if home_mount:
        req_opts = ['nodev', 'nosuid']
        missing = [opt for opt in req_opts if opt not in home_mount['options']]
        results.append({
            "cis_id": "1.1.2.3.2-3",
            "title": "Ensure nodev and nosuid are set on /home",
            "status": "FAIL" if missing else "PASS",
            "message": f"Missing options on /home: {missing}" if missing else "/home has nodev and nosuid.",
            "vulnerability": "Prevents users from placing device files or SUID binaries inside their home directories.",
            "tier": 1
        })
    else:
        results.append({
            "cis_id": "1.1.2.3.2-3", "title": "Ensure nodev and nosuid are set on /home",
            "status": "N/A", "message": "N/A - /home is not on a separate partition in /etc/fstab.", "vulnerability": "N/A", "tier": 1
        })

    return results

def audit_critical_file_perms():
    """CIS 7.1.x: passwd, shadow, group, gshadow, opasswd"""
    results = []

    # Matrix mapping: (CIS_ID, Filepath, Allowed Modes, Owner, Group, Title, Vulnerability)
    # Using lists for Allowed Modes because shadow/gshadow can safely be 0640 OR 0000.
    file_checks = [
        ("7.1.1", "/etc/passwd", ["0644"], "root", "root",
         "Ensure permissions on /etc/passwd are configured",
         "World-writable /etc/passwd would allow any user to inject a backdoor account."),
         
        ("7.1.3", "/etc/group", ["0644"], "root", "root",
         "Ensure permissions on /etc/group are configured",
         "World-writability would let any user add themselves to any group including sudo."),
         
        ("7.1.5", "/etc/shadow", ["0640", "0000"], "root", "shadow",
         "Ensure permissions on /etc/shadow are configured",
         "A world-readable shadow file means any local account can download all password hashes for offline cracking."),
         
        ("7.1.7", "/etc/gshadow", ["0640", "0000"], "root", "shadow",
         "Ensure permissions on /etc/gshadow are configured",
         "Contains group password hashes — same offline cracking risk as /etc/shadow."),
         
        ("7.1.10", "/etc/security/opasswd", ["0600"], "root", "root",
         "Ensure permissions on /etc/security/opasswd are configured",
         "Contains previous password hashes used by pam_pwhistory — must be root-only to prevent history poisoning.")
    ]

    for cis_id, filepath, allowed_modes, expected_owner, expected_group, title, vulnerability in file_checks:
        stat_data = get_file_stat(filepath)
        
        # Safe catch: /etc/security/opasswd only exists if pwhistory is active.
        if not stat_data['exists']:
            results.append({
                "cis_id": cis_id,
                "title": title,
                "status": "PASS", # Or N/A, but PASS is cleaner for non-existent vulnerable files
                "message": f"{filepath} does not exist on this system.",
                "vulnerability": vulnerability,
                "tier": 1
            })
            continue

        # Evaluate permissions and ownership strictly
        errors = []
        if stat_data['mode'] not in allowed_modes:
            errors.append(f"mode is {stat_data['mode']} (expected {allowed_modes})")
        if stat_data['owner'] != expected_owner:
            errors.append(f"owner is {stat_data['owner']} (expected {expected_owner})")
        if stat_data['group'] != expected_group:
            errors.append(f"group is {stat_data['group']} (expected {expected_group})")

        # Construct result dictionary
        results.append({
            "cis_id": cis_id,
            "title": title,
            "status": "FAIL" if errors else "PASS",
            "message": f"Failures on {filepath}: " + ", ".join(errors) if errors else f"{filepath} has correct permissions ({stat_data['mode']} {stat_data['owner']}:{stat_data['group']}).",
            "vulnerability": vulnerability,
            "tier": 1
        })

    return results

def audit_global_file_scans():
    """CIS 7.1.11, 7.1.12: World-writable in /etc, Unowned files"""
    results = []

    # Helper function to execute 'find' safely and cleanly
    def run_find_cmd(cmd_list):
        try:
            # We skip the shell and pass args directly to the binary for maximum security
            # stderr=subprocess.DEVNULL mimics '2>/dev/null' to suppress permission denied errors
            proc = subprocess.run(cmd_list, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, timeout=300)
            return [line.strip() for line in proc.stdout.split('\n') if line.strip()]
        except subprocess.TimeoutExpired:
            return ["TIMEOUT_ERROR: Scan exceeded 5 minutes."]
        except Exception as e:
            return [f"ERROR: {str(e)}"]

    # Helper to truncate massive file lists for the JSON report
    def format_output(file_list):
        if not file_list: return ""
        if len(file_list) <= 5: return str(file_list)
        return f"{file_list[:5]} ... (and {len(file_list) - 5} more)"

    # ---------------------------------------------------------
    # CIS 7.1.11: World-writable files in /etc
    # ---------------------------------------------------------
    ww_etc_cmd = ['find', '/etc', '-xdev', '-type', 'f', '-perm', '-o+w']
    ww_files = run_find_cmd(ww_etc_cmd)
    
    results.append({
        "cis_id": "7.1.11",
        "title": "Ensure no world-writable files exist in /etc",
        "status": "FAIL" if ww_files else "PASS",
        "message": f"World-writable files found: {format_output(ww_files)}" if ww_files else "No world-writable files found in /etc.",
        "vulnerability": "A world-writable config file in /etc lets any local user alter daemon configuration and hijack services.",
        "tier": 1
    })

    # ---------------------------------------------------------
    # CIS 7.1.12: Unowned / Orphaned Files on entire disk
    # ---------------------------------------------------------
    # Note: \( and \) from bash become standard '(' and ')' when passed directly in a Python list
    unowned_cmd = ['find', '/', '-xdev', '(', '-nouser', '-o', '-nogroup', ')']
    unowned_files = run_find_cmd(unowned_cmd)

    results.append({
        "cis_id": "7.1.12",
        "title": "Ensure no orphaned files or directories exist",
        "status": "FAIL" if unowned_files else "PASS",
        "message": f"Orphaned files found: {format_output(unowned_files)}" if unowned_files else "No orphaned files or directories found.",
        "vulnerability": "Orphaned files often indicate a deleted account whose files remain — these can be used to hide malware.",
        "tier": 1
    })

    return results

# ==========================================
# 3. ORCHESTRATION & REPORTING ENGINE
# ==========================================
def main():
    all_results = []

    # 1. Load data natively
    modprobe_data = parse_modprobe()
    fstab_data = parse_fstab()

    # 2. Execute Audits
    all_results.extend(audit_kernel_modules(modprobe_data))
    all_results.extend(audit_fstab_mounts(fstab_data))
    all_results.extend(audit_critical_file_perms())
    all_results.extend(audit_global_file_scans())

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
    output_file = "module2_report.json"
    with open(output_file, "w") as f:
        json.dump(report_data, f, indent=4)

    print(f"\n✅ Module 2 audit complete! {len(passed_or_na)} passed/N/A, {len(failed)} failed.")
    print(f"   Results written to: {os.path.abspath(output_file)}")


if __name__ == "__main__":
    main()