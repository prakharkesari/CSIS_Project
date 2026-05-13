#!/usr/bin/env python3
"""
CIS Ubuntu 22.04 LTS — Module 4 Audit Script
Checks: #76–#100 (Service Surface Audit)
Profile: L1 & L2 Workstation | Source: Benchmark v3.0.0
"""

import os
import sys
import json
import stat
import subprocess

# ==========================================
# 0. EXECUTION CONTEXT VERIFICATION
# ==========================================
if os.geteuid() != 0:
    print("FATAL: This script must be executed as root (sudo python3 module4.py)")
    sys.exit(1)


# ==========================================
# 1. NATIVE CONFIG & DATA LOADERS
# ==========================================

def load_sshd_effective_config() -> dict[str, str]:
    """
    CIS 4.1 SSH: Loads the fully-resolved, effective sshd configuration
    using 'sshd -T' (which applies all Match blocks and defaults).
    Falls back gracefully if openssh-server is not installed.

    Returns a dict of lowercase key -> value, e.g. {'permitrootlogin': 'no'}
    """
    config = {}
    try:
        proc = subprocess.run(
            ['sshd', '-T'],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True
        )
        for line in proc.stdout.splitlines():
            line = line.strip()
            if line and ' ' in line:
                key, _, val = line.partition(' ')
                config[key.lower()] = val.strip().lower()
    except FileNotFoundError:
        pass  # sshd not installed — caller checks is_ssh_installed
    return config


def is_package_installed(pkg_name: str) -> bool:
    """
    CIS 4.2: Checks dpkg for installed packages.
    Returns True only for packages in 'ii' (installed) state.
    """
    try:
        proc = subprocess.run(
            ['dpkg', '-l', pkg_name],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True
        )
        for line in proc.stdout.splitlines():
            if line.startswith('ii'):
                return True
    except Exception:
        pass
    return False


def is_service_active(service_name: str) -> bool:
    """Returns True if a systemd service is currently active/running."""
    try:
        proc = subprocess.run(
            ['systemctl', 'is-active', service_name],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True
        )
        return proc.stdout.strip() == 'active'
    except Exception:
        return False


def get_ufw_status() -> dict:
    """
    CIS 4.3.1: Reads ufw status verbose output and parses it into a
    structured dict for efficient in-memory checks.
    Returns keys: 'active' (bool), 'default_incoming', 'default_outgoing', 'default_routed'
    """
    result = {
        'active': False,
        'default_incoming': None,
        'default_outgoing': None,
        'default_routed': None,
    }
    try:
        proc = subprocess.run(
            ['ufw', 'status', 'verbose'],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True
        )
        output = proc.stdout.lower()
        if 'status: active' in output:
            result['active'] = True
        for line in output.splitlines():
            line = line.strip()
            if line.startswith('default:'):
                # e.g. "default: deny (incoming), allow (outgoing), deny (routed)"
                parts = line[len('default:'):].strip()
                for segment in parts.split(','):
                    segment = segment.strip()
                    if 'incoming' in segment:
                        result['default_incoming'] = 'deny' if 'deny' in segment else 'allow'
                    elif 'outgoing' in segment:
                        result['default_outgoing'] = 'deny' if 'deny' in segment else 'allow'
                    elif 'routed' in segment or 'forward' in segment:
                        result['default_routed'] = 'deny' if 'deny' in segment else 'allow'
    except FileNotFoundError:
        pass
    return result


def get_file_stat(filepath: str) -> dict | None:
    """
    Returns a dict with 'mode' (octal int), 'owner' (str), 'group' (str)
    for a given path. Returns None if file doesn't exist.
    """
    try:
        s = os.stat(filepath)
        import pwd, grp
        owner = pwd.getpwuid(s.st_uid).pw_name
        group = grp.getgrgid(s.st_gid).gr_name
        mode = stat.S_IMODE(s.st_mode)
        return {'mode': mode, 'owner': owner, 'group': group}
    except (FileNotFoundError, KeyError):
        return None


def get_dir_file_stats(dirpath: str) -> list[dict]:
    """
    Returns stat info for all files directly inside a directory (non-recursive).
    Each entry: {'path', 'mode', 'owner', 'group'}
    """
    import pwd, grp
    results = []
    try:
        for entry in os.scandir(dirpath):
            if entry.is_file(follow_symlinks=False):
                s = entry.stat(follow_symlinks=False)
                try:
                    owner = pwd.getpwuid(s.st_uid).pw_name
                    group = grp.getgrgid(s.st_gid).gr_name
                except KeyError:
                    owner = str(s.st_uid)
                    group = str(s.st_gid)
                results.append({
                    'path': entry.path,
                    'mode': stat.S_IMODE(s.st_mode),
                    'owner': owner,
                    'group': group,
                })
    except FileNotFoundError:
        pass
    return results


# ==========================================
# 2. RESULT BUILDER HELPERS
# ==========================================

def _pass(cis_id: str, title: str, tier: int) -> dict:
    return {'cis_id': cis_id, 'title': title, 'status': 'PASS', 'tier': tier}

def _na(cis_id: str, title: str, tier: int) -> dict:
    return {'cis_id': cis_id, 'title': title, 'status': 'N/A', 'tier': tier}

def _fail(cis_id: str, title: str, tier: int, message: str, vulnerability: str) -> dict:
    return {
        'cis_id': cis_id, 'title': title, 'status': 'FAIL', 'tier': tier,
        'message': message, 'vulnerability': vulnerability,
    }


# ==========================================
# 3. AUDIT MODULES
# ==========================================

# ---- 4.1 SSH Server Hardening ----

def audit_ssh_server(sshd_conf: dict, ssh_config_stat: dict | None) -> list[dict]:
    """
    CIS 4.1 (#76–#89): SSH hardening checks.
    All checks are skipped (N/A) if openssh-server is not installed.
    sshd_conf: output of load_sshd_effective_config()
    ssh_config_stat: output of get_file_stat('/etc/ssh/sshd_config')
    """
    results = []

    if not is_package_installed('openssh-server'):
        for cis_id, title, tier in [
            ('5.1.1',  'sshd_config file permissions',          1),
            ('5.1.20', 'PermitRootLogin no',                    1),
            ('5.1.19', 'PermitEmptyPasswords no',               1),
            ('5.1.21', 'PermitUserEnvironment no',              1),
            ('5.1.8',  'AllowTcpForwarding and X11Forwarding',  1),
            ('5.1.10', 'HostbasedAuthentication and Rhosts',    1),
            ('5.1.16', 'MaxAuthTries <= 4',                     1),
            ('5.1.7',  'ClientAlive idle timeout',              1),
            ('5.1.13', 'LoginGraceTime <= 60',                  1),
            ('5.1.22', 'UsePAM yes',                            1),
            ('5.1.14', 'LogLevel VERBOSE',                      1),
            ('5.1.6',  'SSH Ciphers (no weak)',                 3),
            ('5.1.12', 'SSH KexAlgorithms (strong only)',       3),
            ('5.1.15', 'SSH MACs (no MD5/SHA1)',                3),
        ]:
            results.append(_na(cis_id, title, tier))
        return results

    # --- #76 · CIS 5.1.1: sshd_config file permissions ---
    cis_id, title, tier = '5.1.1', 'sshd_config file permissions (600, root:root)', 1
    if ssh_config_stat is None:
        results.append(_fail(cis_id, title, tier,
            "File /etc/ssh/sshd_config does not exist.",
            "Without sshd_config, SSH daemon cannot be configured securely."))
    elif ssh_config_stat['mode'] != 0o600 or ssh_config_stat['owner'] != 'root' or ssh_config_stat['group'] != 'root':
        actual = f"{oct(ssh_config_stat['mode'])} {ssh_config_stat['owner']}:{ssh_config_stat['group']}"
        results.append(_fail(cis_id, title, tier,
            f"Expected 0600 root:root, found {actual}.",
            "World-readable SSH config exposes cipher suite selection and server key paths to any local user."))
    else:
        results.append(_pass(cis_id, title, tier))

    # --- #77 · CIS 5.1.20: PermitRootLogin no ---
    cis_id, title, tier = '5.1.20', 'PermitRootLogin no', 1
    val = sshd_conf.get('permitrootlogin', '')
    if val != 'no':
        results.append(_fail(cis_id, title, tier,
            f"PermitRootLogin is '{val}', expected 'no'.",
            "Direct root SSH login means a brute-forced credential gives immediate full control with no audit trail."))
    else:
        results.append(_pass(cis_id, title, tier))

    # --- #78 · CIS 5.1.19: PermitEmptyPasswords no ---
    cis_id, title, tier = '5.1.19', 'PermitEmptyPasswords no', 1
    val = sshd_conf.get('permitemptypasswords', '')
    if val != 'no':
        results.append(_fail(cis_id, title, tier,
            f"PermitEmptyPasswords is '{val}', expected 'no'.",
            "If any account has an empty password, SSH would grant access with zero authentication."))
    else:
        results.append(_pass(cis_id, title, tier))

    # --- #79 · CIS 5.1.21: PermitUserEnvironment no ---
    cis_id, title, tier = '5.1.21', 'PermitUserEnvironment no', 1
    val = sshd_conf.get('permituserenvironment', '')
    if val != 'no':
        results.append(_fail(cis_id, title, tier,
            f"PermitUserEnvironment is '{val}', expected 'no'.",
            "Allowing users to pass environment variables through SSH can override PATH, LD_PRELOAD, and security settings."))
    else:
        results.append(_pass(cis_id, title, tier))

    # --- #80 · CIS 5.1.8: AllowTcpForwarding no AND X11Forwarding no ---
    cis_id, title, tier = '5.1.8', 'AllowTcpForwarding no and X11Forwarding no', 3
    tcp_fwd = sshd_conf.get('allowtcpforwarding', '')
    x11_fwd = sshd_conf.get('x11forwarding', '')
    issues = []
    if sshd_conf.get('disableforwarding', '') == 'yes':
        results.append(_pass(cis_id, title, tier))
    else:
        if tcp_fwd != 'no':
            issues.append(f"AllowTcpForwarding='{tcp_fwd}' (expected 'no')")
        if x11_fwd != 'no':
            issues.append(f"X11Forwarding='{x11_fwd}' (expected 'no')")
        if issues:
            results.append(_fail(cis_id, title, tier,
                '; '.join(issues),
                "TCP forwarding tunnels arbitrary traffic through SSH; X11 forwarding exposes your display server remotely."))
        else:
            results.append(_pass(cis_id, title, tier))

    # --- #81 · CIS 5.1.10: HostbasedAuthentication no AND IgnoreRhosts yes ---
    cis_id, title, tier = '5.1.10', 'HostbasedAuthentication no and IgnoreRhosts yes', 1
    hba  = sshd_conf.get('hostbasedauthentication', '')
    rhosts = sshd_conf.get('ignorerhosts', '')
    issues = []
    if hba != 'no':
        issues.append(f"HostbasedAuthentication='{hba}' (expected 'no')")
    if rhosts != 'yes':
        issues.append(f"IgnoreRhosts='{rhosts}' (expected 'yes')")
    if issues:
        results.append(_fail(cis_id, title, tier,
            '; '.join(issues),
            "Host-based auth and .rhosts files are 1980s-era trust mechanisms with no authentication — entirely insecure."))
    else:
        results.append(_pass(cis_id, title, tier))

    # --- #82 · CIS 5.1.16: MaxAuthTries <= 4 ---
    cis_id, title, tier = '5.1.16', 'MaxAuthTries <= 4', 1
    raw = sshd_conf.get('maxauthtries', '')
    try:
        val_int = int(raw)
        if val_int > 4:
            results.append(_fail(cis_id, title, tier,
                f"MaxAuthTries is {val_int}, expected <= 4.",
                "Without this, an attacker can attempt unlimited password guesses per connection before disconnecting."))
        else:
            results.append(_pass(cis_id, title, tier))
    except ValueError:
        results.append(_fail(cis_id, title, tier,
            f"MaxAuthTries value '{raw}' could not be parsed.",
            "Without this, an attacker can attempt unlimited password guesses per connection before disconnecting."))

    # --- #83 · CIS 5.1.7: ClientAliveInterval <= 15 AND ClientAliveCountMax <= 3 ---
    cis_id, title, tier = '5.1.7', 'SSH idle timeout (ClientAliveInterval <= 15, CountMax <= 3)', 1
    issues = []
    for key, limit, label in [('clientaliveinterval', 15, 'ClientAliveInterval'), ('clientalivecountmax', 3, 'ClientAliveCountMax')]:
        raw = sshd_conf.get(key, '')
        try:
            v = int(raw)
            if v > limit or (key == 'clientaliveinterval' and v == 0):
                issues.append(f"{label}={v} (expected <= {limit})")
        except ValueError:
            issues.append(f"{label} value '{raw}' could not be parsed")
    if issues:
        results.append(_fail(cis_id, title, tier,
            '; '.join(issues),
            "An unattended idle SSH session left open indefinitely is an open door for anyone with physical access."))
    else:
        results.append(_pass(cis_id, title, tier))

    # --- #84 · CIS 5.1.13: LoginGraceTime <= 60 ---
    cis_id, title, tier = '5.1.13', 'LoginGraceTime <= 60 seconds', 1
    raw = sshd_conf.get('logingracetime', '')
    try:
        val_int = int(raw)
        if val_int > 60 or val_int == 0:
            results.append(_fail(cis_id, title, tier,
                f"LoginGraceTime is {val_int}, expected 1–60.",
                "Limits the authentication window — prevents slow brute-force and connection slot exhaustion."))
        else:
            results.append(_pass(cis_id, title, tier))
    except ValueError:
        results.append(_fail(cis_id, title, tier,
            f"LoginGraceTime value '{raw}' could not be parsed.",
            "Limits the authentication window — prevents slow brute-force and connection slot exhaustion."))

    # --- #85 · CIS 5.1.22: UsePAM yes ---
    cis_id, title, tier = '5.1.22', 'UsePAM yes', 1
    val = sshd_conf.get('usepam', '')
    if val != 'yes':
        results.append(_fail(cis_id, title, tier,
            f"UsePAM is '{val}', expected 'yes'.",
            "Without UsePAM, SSH authentication bypasses faillock, pwquality, and session policies."))
    else:
        results.append(_pass(cis_id, title, tier))

    # --- #86 · CIS 5.1.14: LogLevel VERBOSE ---
    cis_id, title, tier = '5.1.14', 'LogLevel VERBOSE', 1
    val = sshd_conf.get('loglevel', '')
    if val not in ('verbose', 'info'):
        results.append(_fail(cis_id, title, tier,
            f"LogLevel is '{val}', expected 'VERBOSE or info'.",
            "Verbose logging captures the SSH key fingerprint used in each login — essential for forensic attribution."))
    else:
        results.append(_pass(cis_id, title, tier))

    # --- #87 · CIS 5.1.6: No weak SSH ciphers (L2-W, Tier 3) ---
    cis_id, title, tier = '5.1.6', 'SSH Ciphers — no 3des-cbc, arcfour*, aes128-cbc', 3
    ciphers_str = sshd_conf.get('ciphers', '')
    WEAK_CIPHERS = {'3des-cbc', 'aes128-cbc', 'arcfour', 'arcfour128', 'arcfour256'}
    active_ciphers = {c.strip() for c in ciphers_str.split(',')} if ciphers_str else set()
    weak_found = active_ciphers & WEAK_CIPHERS
    # Also catch arcfour* prefix matches
    arcfour_found = {c for c in active_ciphers if c.startswith('arcfour')}
    all_weak = weak_found | arcfour_found
    if all_weak:
        results.append(_fail(cis_id, title, tier,
            f"Weak ciphers present: {', '.join(sorted(all_weak))}.",
            "Weak SSH ciphers allow an attacker recording encrypted sessions to decrypt them offline."))
    else:
        results.append(_pass(cis_id, title, tier))

    # --- #88 · CIS 5.1.12: Strong KexAlgorithms only (L2-W, Tier 3) ---
    cis_id, title, tier = '5.1.12', 'SSH KexAlgorithms — strong algorithms only', 3
    kex_str = sshd_conf.get('kexalgorithms', '')
    WEAK_KEX = {'diffie-hellman-group1-sha1', 'diffie-hellman-group14-sha1',
                'diffie-hellman-group-exchange-sha1', 'gss-gex-sha1-', 'gss-group1-sha1-'}
    active_kex = {k.strip() for k in kex_str.split(',')} if kex_str else set()
    weak_kex = {k for k in active_kex if any(k.startswith(w) for w in WEAK_KEX)}
    if weak_kex:
        results.append(_fail(cis_id, title, tier,
            f"Weak KexAlgorithms present: {', '.join(sorted(weak_kex))}.",
            "Weak key exchange algorithms can be broken with offline compute; DH-group1 (1024-bit) is trivially crackable."))
    else:
        results.append(_pass(cis_id, title, tier))

    # --- #89 · CIS 5.1.15: No MD5/SHA1-based MACs (L2-W, Tier 3) ---
    cis_id, title, tier = '5.1.15', 'SSH MACs — no MD5-based or SHA1-based MACs', 3
    macs_str = sshd_conf.get('macs', '')
    WEAK_MAC_PATTERNS = ['hmac-md5', 'hmac-sha1', 'umac-64', 'hmac-ripemd']
    active_macs = [m.strip() for m in macs_str.split(',')] if macs_str else []
    weak_macs = [m for m in active_macs if any(m.startswith(p) for p in WEAK_MAC_PATTERNS)]
    if weak_macs:
        results.append(_fail(cis_id, title, tier,
            f"Weak MACs present: {', '.join(weak_macs)}.",
            "HMAC-MD5 and HMAC-SHA1 are deprecated; SHA1 collision attacks make message forgery possible."))
    else:
        results.append(_pass(cis_id, title, tier))

    return results


# ---- 4.2 Legacy & Dangerous Service Removal ----

def audit_legacy_services() -> list[dict]:
    """
    CIS 4.2 (#90–#95): Checks that cleartext-protocol packages and FTP/SNMP
    servers are not installed or running. All checks use dpkg and systemd queries
    loaded into memory during function execution.
    """
    results = []

    # --- #90 · CIS 2.2.4: telnet NOT installed ---
    cis_id, title, tier = '2.2.4', 'telnet package not installed', 1
    if is_package_installed('telnet'):
        results.append(_fail(cis_id, title, tier,
            "Package 'telnet' is installed.",
            "Telnet transmits username, password, and all session data in plaintext — trivially captured on any shared network."))
    else:
        results.append(_pass(cis_id, title, tier))

    # --- #91 · CIS 2.2.2: rsh-client NOT installed ---
    cis_id, title, tier = '2.2.2', 'rsh-client package not installed', 1
    if is_package_installed('rsh-client'):
        results.append(_fail(cis_id, title, tier,
            "Package 'rsh-client' is installed.",
            "RSH has zero encryption; entirely superseded by SSH with no legitimate modern use."))
    else:
        results.append(_pass(cis_id, title, tier))

    # --- #92 · CIS 2.2.6: ftp NOT installed ---
    cis_id, title, tier = '2.2.6', 'ftp client package not installed', 1
    if is_package_installed('ftp'):
        results.append(_fail(cis_id, title, tier,
            "Package 'ftp' is installed.",
            "FTP sends credentials in cleartext; use sftp or scp instead."))
    else:
        results.append(_pass(cis_id, title, tier))

    # --- #93 · CIS 2.2.1: nis NOT installed ---
    cis_id, title, tier = '2.2.1', 'NIS (nis package) not installed', 1
    if is_package_installed('nis'):
        results.append(_fail(cis_id, title, tier,
            "Package 'nis' is installed.",
            "NIS is a 1980s-era cleartext directory service; used in targeted attacks as it broadcasts user data."))
    else:
        results.append(_pass(cis_id, title, tier))

    # --- #94 · CIS 2.1.6: FTP servers (vsftpd, proftpd, pure-ftpd) not installed or active ---
    cis_id, title, tier = '2.1.6', 'FTP server daemons not installed or active', 1
    ftp_servers = ['vsftpd', 'proftpd', 'pure-ftpd']
    found_installed = [p for p in ftp_servers if is_package_installed(p)]
    found_active    = [s for s in ftp_servers if is_service_active(s)]
    ftp_issues = []
    if found_installed:
        ftp_issues.append(f"Installed: {', '.join(found_installed)}")
    if found_active:
        ftp_issues.append(f"Active: {', '.join(found_active)}")
    if ftp_issues:
        results.append(_fail(cis_id, title, tier,
            '; '.join(ftp_issues),
            "An FTP server on a personal laptop has no purpose and exposes a cleartext service to the local network."))
    else:
        results.append(_pass(cis_id, title, tier))

    # --- #95 · CIS 2.1.15: snmpd NOT installed or active (Tier 2) ---
    cis_id, title, tier = '2.1.15', 'snmpd not installed or active', 2
    snmp_installed = is_package_installed('snmpd')
    snmp_active    = is_service_active('snmpd')
    if snmp_installed or snmp_active:
        issues = []
        if snmp_installed: issues.append("installed")
        if snmp_active:    issues.append("active")
        results.append(_fail(cis_id, title, tier,
            f"snmpd is {' and '.join(issues)}.",
            "SNMP v1/v2c community strings are cleartext passwords; v1 is trivially sniffable on any LAN."))
    else:
        results.append(_pass(cis_id, title, tier))

    return results


# ---- 4.3 Firewall & Scheduled Task Policy ----

def audit_firewall_and_cron(ufw_status: dict, crontab_stat: dict | None, crond_stat: dict | None, crond_files: list[dict]) -> list[dict]:
    """
    CIS 4.3 (#96–#100): UFW firewall posture and cron directory permissions.
    All data is pre-loaded into memory; no subprocess calls inside this function.
    """
    results = []

    # --- #96 · CIS 4.1.1: ufw installed and active ---
    cis_id, title, tier = '4.1.1', 'ufw installed and active', 1
    ufw_pkg = is_package_installed('ufw')
    if not ufw_pkg:
        results.append(_fail(cis_id, title, tier,
            "Package 'ufw' is not installed.",
            "Without a firewall, every service listening on any port is reachable from the local network by default."))
    elif not ufw_status['active']:
        results.append(_fail(cis_id, title, tier,
            "ufw is installed but not active (Status: inactive).",
            "Without a firewall, every service listening on any port is reachable from the local network by default."))
    else:
        results.append(_pass(cis_id, title, tier))

    # --- #97 · CIS 4.1.3: Default incoming policy is DENY ---
    cis_id, title, tier = '4.1.3', 'ufw default incoming policy is DENY', 1
    if not ufw_status['active']:
        results.append(_fail(cis_id, title, tier,
            "ufw is not active; cannot evaluate default policy.",
            "Fail-closed firewall stance requires ufw to be active with incoming denied by default."))
    elif ufw_status['default_incoming'] != 'deny':
        actual = ufw_status['default_incoming'] or 'unknown'
        results.append(_fail(cis_id, title, tier,
            f"Default incoming policy is '{actual}', expected 'deny'.",
            "Fail-closed firewall stance: deny everything by default and open only what is explicitly needed."))
    else:
        results.append(_pass(cis_id, title, tier))

    # --- #98 · CIS 4.1.5: Default forwarded/routed traffic policy is DROP/DENY ---
    cis_id, title, tier = '4.1.5', 'ufw default routed/forwarded policy is DENY', 1
    if not ufw_status['active']:
        results.append(_fail(cis_id, title, tier,
            "ufw is not active; cannot evaluate forward policy.",
            "A personal laptop must not forward traffic between its interfaces — that is router behaviour."))
    elif ufw_status['default_routed'] != 'deny':
        actual = ufw_status['default_routed'] or 'unknown/not set'
        results.append(_fail(cis_id, title, tier,
            f"Default routed policy is '{actual}', expected 'deny'.",
            "A personal laptop must not forward traffic between its interfaces — that is router behaviour."))
    else:
        results.append(_pass(cis_id, title, tier))

    # --- #99 · CIS 2.4.1.2: /etc/crontab permissions 0600, owner root:root ---
    cis_id, title, tier = '2.4.1.2', '/etc/crontab permissions 0600, root:root', 1
    if crontab_stat is None:
        results.append(_na(cis_id, title, tier))
    else:
        issues = []
        if crontab_stat['mode'] != 0o600:
            issues.append(f"mode is {oct(crontab_stat['mode'])} (expected 0600)")
        if crontab_stat['owner'] != 'root':
            issues.append(f"owner is '{crontab_stat['owner']}' (expected root)")
        if crontab_stat['group'] != 'root':
            issues.append(f"group is '{crontab_stat['group']}' (expected root)")
        if issues:
            results.append(_fail(cis_id, title, tier,
                f"/etc/crontab: {'; '.join(issues)}.",
                "A world-readable or world-writable crontab lets any user read scheduled commands or inject their own."))
        else:
            results.append(_pass(cis_id, title, tier))

    # --- #100 · CIS 2.4.1.8: /etc/cron.d/ directory 0700 root:root; files 0600 root:root ---
    cis_id, title, tier = '2.4.1.8', '/etc/cron.d/ directory 0700 root:root; files 0600', 1
    issues = []
    if crond_stat is None:
        results.append(_na(cis_id, title, tier))
    else:
        if crond_stat['mode'] != 0o700:
            issues.append(f"Directory mode is {oct(crond_stat['mode'])} (expected 0700)")
        if crond_stat['owner'] != 'root':
            issues.append(f"Directory owner is '{crond_stat['owner']}' (expected root)")
        if crond_stat['group'] != 'root':
            issues.append(f"Directory group is '{crond_stat['group']}' (expected root)")
        # Check individual files inside /etc/cron.d/
        bad_files = []
        for f in crond_files:
            file_issues = []
            if f['mode'] != 0o600 and not os.path.basename(f['path']).startswith('.'):
                file_issues.append(f"mode={oct(f['mode'])}")
            if f['owner'] != 'root':
                file_issues.append(f"owner={f['owner']}")
            if f['group'] != 'root':
                file_issues.append(f"group={f['group']}")
            if file_issues:
                bad_files.append(f"{os.path.basename(f['path'])} ({', '.join(file_issues)})")
        if bad_files:
            issues.append(f"Files with bad permissions: {', '.join(bad_files)}")

        if issues:
            results.append(_fail(cis_id, title, tier,
                '; '.join(issues),
                "Drop-in cron job files in /etc/cron.d/ must be root-exclusive; other users must not add scheduled tasks here."))
        else:
            results.append(_pass(cis_id, title, tier))

    return results


# ==========================================
# 4. ORCHESTRATION & REPORTING ENGINE
# ==========================================

def main():
    all_results = []

    # 1. Load all data natively (single read per source)
    sshd_conf        = load_sshd_effective_config()
    ssh_config_stat  = get_file_stat('/etc/ssh/sshd_config')
    ufw_status       = get_ufw_status()
    crontab_stat     = get_file_stat('/etc/crontab')
    crond_stat       = get_file_stat('/etc/cron.d')
    crond_files      = get_dir_file_stats('/etc/cron.d')

    # 2. Execute Audits
    all_results.extend(audit_ssh_server(sshd_conf, ssh_config_stat))
    all_results.extend(audit_legacy_services())
    all_results.extend(audit_firewall_and_cron(ufw_status, crontab_stat, crond_stat, crond_files))

    # 3. Segregate Results
    passed_or_na = [r for r in all_results if r['status'] in ('PASS', 'N/A')]
    failed       = [r for r in all_results if r['status'] == 'FAIL']
    failed.sort(key=lambda x: x.get('tier', 1))

    # 4. Construct JSON Structure
    report_data = {
        "module": "Module 4 — Service Surface Audit",
        "total_checks": len(all_results),
        "passed_or_na": len(passed_or_na),
        "failed": len(failed),
        "compliant_and_na_checks": [
            f"{r['cis_id']} — {r['title']} ({r['status']})" for r in passed_or_na
        ],
        "failures_by_tier": {"tier_1": [], "tier_2": [], "tier_3": []}
    }

    for item in failed:
        tier_key = f"tier_{item.get('tier', 1)}"
        report_data["failures_by_tier"][tier_key].append({
            "cis_id":        item['cis_id'],
            "title":         item['title'],
            "message":       item['message'],
            "vulnerability": item['vulnerability'],
        })

    # Clean up empty tiers
    report_data["failures_by_tier"] = {
        k: v for k, v in report_data["failures_by_tier"].items() if v
    }

    # 5. Output JSON Report
    output_file = "module4_report.json"
    with open(output_file, "w") as f:
        json.dump(report_data, f, indent=4)

    print(f"\n✅ Module 4 audit complete! {len(passed_or_na)} passed/N/A, {len(failed)} failed.")
    print(f"   Results written to: {os.path.abspath(output_file)}")


if __name__ == "__main__":
    main()
