#!/usr/bin/env python3
import os
import sys
import stat
import pwd
import grp
import json

# ==========================================
# 0. EXECUTION CONTEXT VERIFICATION
# ==========================================
if os.geteuid() != 0:
    print("FATAL: This script must be executed as root (sudo python3 module1_identity_v2.py)")
    sys.exit(1)

# ==========================================
# 1. NATIVE FILE PARSERS & QUERIES
# ==========================================

def get_file_stat(filepath):
    """Natively retrieves octal permissions, owner, and group safely."""
    try:
        file_stat = os.stat(filepath)
        # Using the octal formatting fix we learned in Module 2
        mode = f"{stat.S_IMODE(file_stat.st_mode):04o}"
        owner = pwd.getpwuid(file_stat.st_uid).pw_name
        group = grp.getgrgid(file_stat.st_gid).gr_name
        return {'exists': True, 'mode': mode, 'owner': owner, 'group': group}
    except FileNotFoundError:
        return {'exists': False}

def parse_colon_separated(filepath, key_index=0):
    """Parses files like passwd, shadow, group into a dictionary."""
    data = {}
    try:
        with open(filepath, 'r') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                parts = line.split(':')
                data[parts[key_index]] = parts
    except FileNotFoundError:
        pass
    return data

def parse_key_value_config(filepath, separator=' ', ignore_equals=False):
    """Parses config files like login.defs or pwquality.conf into a dict."""
    data = {}
    try:
        with open(filepath, 'r') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                # Handle both "KEY VALUE" and "KEY=VALUE" formats
                if not ignore_equals and '=' in line:
                    k, v = line.split('=', 1)
                else:
                    parts = line.split(None, 1)
                    k = parts[0]
                    v = parts[1] if len(parts) > 1 else ""
                data[k.strip()] = v.strip()
    except FileNotFoundError:
        pass
    return data

# ==========================================
# 2. AUDIT MODULES (Logic)
# ==========================================

def audit_account_integrity(passwd_data, group_data, login_defs_data):
    """CIS 1.1: UID 0, duplicate UIDs/GIDs, system account shells."""
    results = []

    # ---------------------------------------------------------
    # CIS 5.4.2.1: Ensure only root has UID 0
    # ---------------------------------------------------------
    rogue_uid0 = []
    for user, fields in passwd_data.items():
        if len(fields) > 2 and fields[2] == '0' and user != 'root':
            rogue_uid0.append(user)
            
    results.append({
        "cis_id": "5.4.2.1",
        "title": "Ensure only root has UID 0",
        "status": "FAIL" if rogue_uid0 else "PASS",
        "message": f"Rogue UID 0 accounts found: {rogue_uid0}" if rogue_uid0 else "Only root has UID 0.",
        "vulnerability": "A second UID-0 account is a root-level backdoor — classic persistence technique after system compromise.",
        "tier": 1
    })

    # ---------------------------------------------------------
    # CIS 7.2.5: Ensure no duplicate UIDs exist
    # ---------------------------------------------------------
    uid_map = {}
    for user, fields in passwd_data.items():
        if len(fields) > 2:
            uid = fields[2]
            uid_map.setdefault(uid, []).append(user)
    
    dup_uids = {uid: users for uid, users in uid_map.items() if len(users) > 1}
    results.append({
        "cis_id": "7.2.5",
        "title": "Ensure no duplicate UIDs exist",
        "status": "FAIL" if dup_uids else "PASS",
        "message": f"Duplicate UIDs found: {dup_uids}" if dup_uids else "No duplicate UIDs exist.",
        "vulnerability": "Same UID lets one user masquerade as another, silently inheriting all their file permissions.",
        "tier": 1
    })

    # ---------------------------------------------------------
    # CIS 7.2.6: Ensure no duplicate GIDs exist
    # ---------------------------------------------------------
    gid_map = {}
    for group, fields in group_data.items():
        if len(fields) > 2:
            gid = fields[2]
            gid_map.setdefault(gid, []).append(group)
            
    dup_gids = {gid: groups for gid, groups in gid_map.items() if len(groups) > 1}
    results.append({
        "cis_id": "7.2.6",
        "title": "Ensure no duplicate GIDs exist",
        "status": "FAIL" if dup_gids else "PASS",
        "message": f"Duplicate GIDs found: {dup_gids}" if dup_gids else "No duplicate GIDs exist.",
        "vulnerability": "Duplicate GIDs break ACL isolation — two groups unintentionally share the same permission set.",
        "tier": 1
    })

    # ---------------------------------------------------------
    # Helper for 7.2.7 and 7.2.8: Bypass Dict Key Uniqueness
    # ---------------------------------------------------------
    def find_duplicate_names(filepath):
        names = set()
        dups = set()
        try:
            with open(filepath, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'): 
                        continue
                    name = line.split(':')[0]
                    if name in names:
                        dups.add(name)
                    else:
                        names.add(name)
        except Exception:
            pass
        return list(dups)

    # ---------------------------------------------------------
    # CIS 7.2.7: Ensure no duplicate usernames exist
    # ---------------------------------------------------------
    dup_users = find_duplicate_names('/etc/passwd')
    results.append({
        "cis_id": "7.2.7",
        "title": "Ensure no duplicate usernames exist",
        "status": "FAIL" if dup_users else "PASS",
        "message": f"Duplicate usernames found: {dup_users}" if dup_users else "No duplicate usernames exist.",
        "vulnerability": "Duplicate usernames cause shell-level ambiguity that can be exploited to misidentify the acting user.",
        "tier": 1
    })

    # ---------------------------------------------------------
    # CIS 7.2.8: Ensure no duplicate group names exist
    # ---------------------------------------------------------
    dup_groups = find_duplicate_names('/etc/group')
    results.append({
        "cis_id": "7.2.8",
        "title": "Ensure no duplicate group names exist",
        "status": "FAIL" if dup_groups else "PASS",
        "message": f"Duplicate group names found: {dup_groups}" if dup_groups else "No duplicate group names exist.",
        "vulnerability": "Inconsistent group resolution breaks permission logic silently and is hard to debug.",
        "tier": 1
    })

    # ---------------------------------------------------------
    # CIS 5.4.2.7: Ensure system accounts are non-login
    # ---------------------------------------------------------
    # Dynamically extract UID_MIN from login.defs (defaulting to 1000 if not found)
    uid_min = int(login_defs_data.get('UID_MIN', 1000))
    valid_shells = ['/sbin/nologin', '/bin/false', '/usr/sbin/nologin']
    
    # Typical system accounts that are exempt from the nologin rule by design
    exempt_accounts = {'root', 'sync', 'shutdown', 'halt'}
    
    rogue_daemons = []
    for user, fields in passwd_data.items():
        if len(fields) >= 7:
            try:
                uid = int(fields[2])
                shell = fields[6]
                if uid < uid_min and user not in exempt_accounts:
                    if shell not in valid_shells:
                        rogue_daemons.append(f"{user} ({shell})")
            except ValueError:
                continue

    results.append({
        "cis_id": "5.4.2.7",
        "title": "Ensure system accounts are non-login",
        "status": "FAIL" if rogue_daemons else "PASS",
        "message": f"System accounts with active shells found: {rogue_daemons}" if rogue_daemons else "All system accounts have restricted shells.",
        "vulnerability": "Daemon accounts with a real shell can be exploited as interactive login targets if their password is ever set.",
        "tier": 1
    })

    return results

def audit_shadow_hygiene(shadow_data, passwd_data):
    """CIS 1.2: Hashing, empty passwords, locked daemons, root login."""
    results = []

    # ---------------------------------------------------------
    # CIS 7.2.1: Ensure shadowing is active (passwd field 2 is 'x')
    # ---------------------------------------------------------
    unshadowed = []
    for user, fields in passwd_data.items():
        if len(fields) > 1 and fields[1] != 'x':
            unshadowed.append(user)

    results.append({
        "cis_id": "7.2.1",
        "title": "Ensure shadowing is active ('x' in passwd)",
        "status": "FAIL" if unshadowed else "PASS",
        "message": f"Accounts with exposed hashes in /etc/passwd: {unshadowed}" if unshadowed else "All accounts are properly shadowed.",
        "vulnerability": "A literal password hash in /etc/passwd is world-readable by every local user — trivially crackable offline.",
        "tier": 1
    })

    # ---------------------------------------------------------
    # CIS 7.2.2: Ensure no account has an empty password field
    # ---------------------------------------------------------
    empty_pass = []
    for user, fields in shadow_data.items():
        # A truly empty password field allows login without authentication
        if len(fields) > 1 and fields[1] in ('', ' '):
            empty_pass.append(user)

    results.append({
        "cis_id": "7.2.2",
        "title": "Ensure no account has an empty password field",
        "status": "FAIL" if empty_pass else "PASS",
        "message": f"Accounts with empty passwords found: {empty_pass}" if empty_pass else "No accounts have empty passwords.",
        "vulnerability": "An empty password field means the account requires zero authentication — complete access control bypass.",
        "tier": 1
    })

    # ---------------------------------------------------------
    # CIS 5.4.2.8: Ensure non-login system users are locked
    # ---------------------------------------------------------
    # Fixing the PDF Bug: We safely cross-reference the UID from passwd_data
    unlocked_daemons = []
    for user, fields in shadow_data.items():
        if len(fields) > 1:
            pwd_hash = fields[1]
            
            # Retrieve the matched user from the passwd dictionary
            passwd_entry = passwd_data.get(user)
            if passwd_entry and len(passwd_entry) > 2:
                try:
                    uid = int(passwd_entry[2])
                    # Evaluate System Accounts (UID < 1000). Exclude root (UID 0) as it is evaluated in 5.4.2.4
                    if 0 < uid < 1000:
                        # A locked account hash begins with '!' or '*'
                        if not pwd_hash.startswith(('!', '*')):
                            unlocked_daemons.append(user)
                except ValueError:
                    continue

    results.append({
        "cis_id": "5.4.2.8",
        "title": "Ensure non-login system users are locked",
        "status": "FAIL" if unlocked_daemons else "PASS",
        "message": f"Unlocked system daemons found: {unlocked_daemons}" if unlocked_daemons else "All system daemons are correctly locked.",
        "vulnerability": "An unlocked daemon account can be brute-forced or abused if a vulnerability allows shell execution as that user.",
        "tier": 1
    })

    # ---------------------------------------------------------
    # CIS 5.4.2.4: Ensure root account has no direct password login
    # ---------------------------------------------------------
    root_shadow = shadow_data.get('root')
    root_locked = False
    
    if root_shadow and len(root_shadow) > 1:
        pwd_hash = root_shadow[1]
        if pwd_hash.startswith(('!', '*')):
            root_locked = True
            
    results.append({
        "cis_id": "5.4.2.4",
        "title": "Ensure root account has no direct password login",
        "status": "PASS" if root_locked else "FAIL",
        "message": "Root account is correctly locked in /etc/shadow." if root_locked else "Root account is NOT locked. Direct root auth is possible.",
        "vulnerability": "Direct root auth bypasses user-level audit trail — all root actions should flow through sudo for traceability.",
        "tier": 1
    })

    return results

def audit_root_environment():
    """CIS 1.2 (Check 10b): Root PATH integrity and Umask."""
    results = []

    # ---------------------------------------------------------
    # CIS 5.4.2.6 (10b): Root Umask
    # ---------------------------------------------------------
    root_files = ['/root/.profile', '/root/.bashrc']
    failing_umasks = []
    found_umask = False

    for filepath in root_files:
        try:
            with open(filepath, 'r') as f:
                for line in f:
                    line = line.strip()
                    # Look for explicit umask commands
                    if line.startswith('#') or not line.startswith('umask'):
                        continue
                    
                    parts = line.split()
                    if len(parts) >= 2:
                        found_umask = True
                        umask_str = parts[1]
                        try:
                            # Convert string (e.g., '027' or '0027') to base-8 integer
                            umask_val = int(umask_str, 8)
                            
                            # Bitwise check: Ensures at least the 027 restrictive bits are set
                            if (umask_val & 0o027) != 0o027:
                                failing_umasks.append(f"{filepath}: {umask_str}")
                        except ValueError:
                            failing_umasks.append(f"{filepath}: invalid format '{umask_str}'")
        except FileNotFoundError:
            continue
            
    # Determine Pass/Fail logic based on findings
    if not found_umask:
        status = "FAIL"
        msg = "No explicit umask configuration found in /root/.profile or /root/.bashrc. Default may be too permissive."
    elif failing_umasks:
        status = "FAIL"
        msg = f"Permissive umask settings found: {failing_umasks} (Expected 027 or stricter)."
    else:
        status = "PASS"
        msg = "Root umask is explicitly set to 027 or stricter."

    results.append({
        "cis_id": "5.4.2.6",
        "title": "Ensure root user umask is configured",
        "status": status,
        "message": msg,
        "vulnerability": "A permissive root umask means newly created root files are world-readable by default.",
        "tier": 1
    })

    return results

def audit_password_aging(login_defs_data):
    """CIS 1.3: PASS_MAX_DAYS, PASS_WARN_AGE, Encryption, and Inactive accounts."""
    results = []

    # Helper to safely convert configuration strings to integers
    def safe_int(value, default=-999):
        try:
            return int(value)
        except (ValueError, TypeError):
            return default

    # ---------------------------------------------------------
    # CIS 5.4.1.1: Ensure password expiration is 365 days or less
    # ---------------------------------------------------------
    pass_max_days_raw = login_defs_data.get('PASS_MAX_DAYS')
    pass_max_days = safe_int(pass_max_days_raw)
    
    results.append({
        "cis_id": "5.4.1.1",
        "title": "Ensure password expiration is 365 days or less",
        "status": "PASS" if 0 < pass_max_days <= 365 else "FAIL",
        "message": f"PASS_MAX_DAYS is set to {pass_max_days_raw} (Expected: <= 365)." if pass_max_days_raw else "PASS_MAX_DAYS is missing from configuration.",
        "vulnerability": "Without a maximum age, a compromised credential remains valid indefinitely with no forced rotation.",
        "tier": 1
    })

    # ---------------------------------------------------------
    # CIS 5.4.1.3: Ensure password expiration warning days is 7 or more
    # ---------------------------------------------------------
    pass_warn_age_raw = login_defs_data.get('PASS_WARN_AGE')
    pass_warn_age = safe_int(pass_warn_age_raw)

    results.append({
        "cis_id": "5.4.1.3",
        "title": "Ensure password expiration warning days is 7 or more",
        "status": "PASS" if pass_warn_age >= 7 else "FAIL",
        "message": f"PASS_WARN_AGE is set to {pass_warn_age_raw} (Expected: >= 7)." if pass_warn_age_raw else "PASS_WARN_AGE is missing from configuration.",
        "vulnerability": "Advance warning prevents unexpected lockout — users aren't surprised by expired passwords.",
        "tier": 1
    })

    # ---------------------------------------------------------
    # CIS 5.4.1.4: Ensure password hashing algorithm is strong
    # ---------------------------------------------------------
    encrypt_method = login_defs_data.get('ENCRYPT_METHOD', '')
    allowed_methods = ['yescrypt', 'SHA512', 'SHA256']
    
    results.append({
        "cis_id": "5.4.1.4",
        "title": "Ensure password hashing algorithm is strong",
        "status": "PASS" if encrypt_method in allowed_methods else "FAIL",
        "message": f"ENCRYPT_METHOD is set to '{encrypt_method}'." if encrypt_method else "ENCRYPT_METHOD is missing from configuration.",
        "vulnerability": "MD5 and DES hashes are crackable in seconds with modern GPUs — yescrypt is the current recommended standard.",
        "tier": 1
    })

    # ---------------------------------------------------------
    # CIS 5.4.1.5: Ensure inactive password lock is 30 days or less
    # ---------------------------------------------------------
    # Dynamically utilize our Phase 1 global parser for /etc/default/useradd (which uses KEY=VALUE format)
    useradd_data = parse_key_value_config('/etc/default/useradd')
    inactive_raw = useradd_data.get('INACTIVE')
    
    # We default to 999 so a missing key natively triggers the FAIL condition (since it exceeds 30)
    inactive_val = safe_int(inactive_raw, default=999) 

    # -1 means disabled, which is a failure condition. Value must be between 0 and 30.
    results.append({
        "cis_id": "5.4.1.5",
        "title": "Ensure inactive password lock is 30 days or less",
        "status": "PASS" if 0 <= inactive_val <= 30 else "FAIL",
        "message": f"INACTIVE is set to {inactive_raw} (Expected: 0 to 30)." if inactive_raw else "INACTIVE is not configured or disabled.",
        "vulnerability": "Dormant accounts are ideal targets because legitimate owners don't notice when they're abused.",
        "tier": 1
    })

    return results

def audit_pam_and_auth():
    """CIS 1.4 & 1.5: pwquality, faillock, PAM modules, sudoers."""
    import os
    import re
    results = []

    def safe_int(value, default=-999):
        try:
            return int(value)
        except (ValueError, TypeError):
            return default

    # --- Config Loaders ---
    # Re-using the global parser from the Phase 1 skeleton
    pwquality_data = parse_key_value_config('/etc/security/pwquality.conf')
    faillock_data = parse_key_value_config('/etc/security/faillock.conf')

    # Helper to load and strip comments from a single file
    def get_clean_lines(filepath):
        lines = []
        try:
            with open(filepath, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        lines.append(line)
        except FileNotFoundError:
            pass
        return lines

    # Load PAM configurations
    pam_password = get_clean_lines('/etc/pam.d/common-password')
    pam_su = get_clean_lines('/etc/pam.d/su')

    # Helper to load all sudoers configurations (/etc/sudoers + /etc/sudoers.d/*)
    sudoers_lines = get_clean_lines('/etc/sudoers')
    if os.path.isdir('/etc/sudoers.d'):
        for file in os.listdir('/etc/sudoers.d'):
            filepath = os.path.join('/etc/sudoers.d', file)
            if os.path.isfile(filepath):
                sudoers_lines.extend(get_clean_lines(filepath))

    # =========================================================
    # 1.4 PASSWORD QUALITY (pwquality.conf & PAM)
    # =========================================================

    # CIS 5.3.3.2.2: minlen >= 14
    minlen_val = safe_int(pwquality_data.get('minlen'))
    results.append({
        "cis_id": "5.3.3.2.2", "title": "Ensure password length is 14 or more",
        "status": "PASS" if minlen_val >= 14 else "FAIL",
        "message": f"minlen is {minlen_val} (Expected >= 14)." if minlen_val != -999 else "minlen not configured.",
        "vulnerability": "Password length is the single most impactful factor in resistance to brute-force and offline dictionary attacks.",
        "tier": 1
    })

    # CIS 5.3.3.2.1: difok >= 2
    difok_val = safe_int(pwquality_data.get('difok'))
    results.append({
        "cis_id": "5.3.3.2.1", "title": "Ensure password changing requires at least 2 different characters",
        "status": "PASS" if difok_val >= 2 else "FAIL",
        "message": f"difok is {difok_val} (Expected >= 2)." if difok_val != -999 else "difok not configured.",
        "vulnerability": "Without difok, a user can change 'password1' to 'password2' — meaningless rotation.",
        "tier": 1
    })

    # CIS 5.3.3.2.4: maxrepeat <= 3
    maxrep_val = safe_int(pwquality_data.get('maxrepeat'), default=999)
    results.append({
        "cis_id": "5.3.3.2.4", "title": "Ensure maximum repeated characters is 3 or less",
        "status": "PASS" if 1 <= maxrep_val <= 3 else "FAIL",
        "message": f"maxrepeat is {maxrep_val} (Expected <= 3)." if maxrep_val != 999 else "maxrepeat not configured.",
        "vulnerability": "Catches trivially weak passwords like 'aaaa1234' that meet length but not quality requirements.",
        "tier": 1
    })

    # CIS 5.3.3.2.6: dictcheck = 1
    dict_val = safe_int(pwquality_data.get('dictcheck'))
    results.append({
        "cis_id": "5.3.3.2.6", "title": "Ensure dictionary word checks are enabled",
        "status": "PASS" if dict_val == 1 else "FAIL",
        "message": f"dictcheck is {dict_val} (Expected 1)." if dict_val != -999 else "dictcheck not configured.",
        "vulnerability": "Blocks use of common English dictionary words — first target of any password spray attack.",
        "tier": 1
    })

    # CIS 5.3.3.2.7: pam_pwquality.so retry=3
    pwq_pam = [l for l in pam_password if "pam_pwquality.so" in l and "retry=" in l]
    results.append({
        "cis_id": "5.3.3.2.7", "title": "Ensure pam_pwquality.so is active and retry limits are set",
        "status": "PASS" if pwq_pam else "FAIL",
        "message": "pam_pwquality.so with retry configured." if pwq_pam else "pam_pwquality.so missing or lacks retry limit.",
        "vulnerability": "Without this PAM line, pwquality.conf settings exist but are never actually enforced at login.",
        "tier": 1
    })

    # CIS 5.3.3.4.1: No nullok
    nullok_found = [l for l in pam_password if "pam_unix.so" in l and "nullok" in l]
    results.append({
        "cis_id": "5.3.3.4.1", "title": "Ensure null passwords are not accepted",
        "status": "FAIL" if nullok_found else "PASS",
        "message": "nullok is present on pam_unix.so." if nullok_found else "nullok is not present.",
        "vulnerability": "nullok instructs PAM to accept empty/null passwords as valid — complete auth bypass.",
        "tier": 1
    })

    # CIS 5.3.3.4.3: Strong hashing in PAM (sha512 or yescrypt)
    strong_hash = [l for l in pam_password if "pam_unix.so" in l and ("sha512" in l or "yescrypt" in l)]
    results.append({
        "cis_id": "5.3.3.4.3", "title": "Ensure strong password hashing algorithm in PAM",
        "status": "PASS" if strong_hash else "FAIL",
        "message": "Strong hashing (sha512/yescrypt) enforced by PAM." if strong_hash else "pam_unix.so missing strong hash argument.",
        "vulnerability": "Enforces strong hash algorithm at the PAM layer regardless of login.defs setting.",
        "tier": 1
    })

    # CIS 5.3.3.3.1: pam_pwhistory remember>=24
    history_line = next((l for l in pam_password if "pam_pwhistory.so" in l and "remember=" in l), None)
    remember_val = int(re.search(r'remember=(\d+)', history_line).group(1)) if history_line else 0 # type: ignore
    results.append({
        "cis_id": "5.3.3.3.1", "title": "Ensure password history is 24 or greater",
        "status": "PASS" if remember_val >= 24 else "FAIL",
        "message": f"Password history remember is {remember_val}." if history_line else "pam_pwhistory.so not found or remember not set.",
        "vulnerability": "Prevents reuse of the last 24 passwords — without it a user immediately re-uses their old password.",
        "tier": 1
    })

    # =========================================================
    # 1.5 LOCKOUT, SUDO & SHELL POLICY
    # =========================================================

    # CIS 5.3.3.1.1: deny <= 5
    deny_val = safe_int(faillock_data.get('deny'), default=999)
    results.append({
        "cis_id": "5.3.3.1.1", "title": "Ensure failed password attempts lockout is 5 or less",
        "status": "PASS" if 0 < deny_val <= 5 else "FAIL",
        "message": f"deny is {deny_val} (Expected <= 5)." if deny_val != 999 else "deny not configured in faillock.conf.",
        "vulnerability": "Core brute-force protection — without it, an attacker can attempt unlimited passwords at login.",
        "tier": 1
    })

    # CIS 5.3.3.1.2: unlock_time >= 900
    unlock_val = safe_int(faillock_data.get('unlock_time'))
    results.append({
        "cis_id": "5.3.3.1.2", "title": "Ensure lockout time is 15 minutes or longer",
        "status": "PASS" if unlock_val >= 900 else "FAIL",
        "message": f"unlock_time is {unlock_val} (Expected >= 900)." if unlock_val != -999 else "unlock_time not configured.",
        "vulnerability": "A short lockout window is trivially bypassed — 15 minutes defeats automated brute-force tools.",
        "tier": 1
    })

    # CIS 5.2.4: NOPASSWD in sudoers
    nopasswd = [l for l in sudoers_lines if "NOPASSWD" in l]
    results.append({
        "cis_id": "5.2.4", "title": "Ensure no NOPASSWD entries exist in sudoers",
        "status": "FAIL" if nopasswd else "PASS",
        "message": "NOPASSWD entries found in sudo configuration." if nopasswd else "No NOPASSWD entries found.",
        "vulnerability": "NOPASSWD allows escalation to root without any authentication.",
        "tier": 1
    })

    # CIS 5.2.5: !authenticate in sudoers
    no_auth = [l for l in sudoers_lines if "!authenticate" in l]
    results.append({
        "cis_id": "5.2.5", "title": "Ensure re-authentication is not disabled in sudoers",
        "status": "FAIL" if no_auth else "PASS",
        "message": "!authenticate entries found in sudo configuration." if no_auth else "No !authenticate entries found.",
        "vulnerability": "Disabling re-auth means sudo never prompts for a password again — permanent root-level token.",
        "tier": 1
    })

    # CIS 5.2.2: use_pty in sudoers
    use_pty = [l for l in sudoers_lines if "use_pty" in l]
    results.append({
        "cis_id": "5.2.2", "title": "Ensure sudo commands use pty",
        "status": "PASS" if use_pty else "FAIL",
        "message": "use_pty is explicitly configured." if use_pty else "use_pty is missing from Defaults.",
        "vulnerability": "Prevents sudo from being invoked in non-interactive scripts without a TTY.",
        "tier": 1
    })

    # CIS 5.2.3: logfile in sudoers
    logfile = [l for l in sudoers_lines if "logfile=" in l.replace(" ", "")]
    results.append({
        "cis_id": "5.2.3", "title": "Ensure a custom sudo log file exists",
        "status": "PASS" if logfile else "FAIL",
        "message": "Sudo logfile is configured." if logfile else "logfile parameter is missing from Defaults.",
        "vulnerability": "Without a dedicated sudo log file, all sudo activity is buried in syslog and easy to miss.",
        "tier": 1
    })

    # CIS 5.2.6: timestamp_timeout in sudoers
    timeout_line = next((l for l in sudoers_lines if "timestamp_timeout=" in l), None)
    timeout_val = int(re.search(r'timestamp_timeout=(-?\d+)', timeout_line).group(1)) if timeout_line else -999 # type: ignore
    results.append({
        "cis_id": "5.2.6", "title": "Ensure sudo authentication timeout is configured correctly",
        # Allow values 0 through 15. Negative values are a critical failure.
        "status": "PASS" if timeout_line and 0 <= timeout_val <= 15 else "FAIL",
        "message": f"timestamp_timeout is {timeout_val} (Expected 0 to 15)." if timeout_line else "timestamp_timeout not explicitly set.",
        "vulnerability": "A negative timeout value disables re-prompting entirely — an unattended terminal stays permanently escalated.",
        "tier": 1
    })

    # CIS 5.2.7: pam_wheel.so in /etc/pam.d/su
    wheel_su = [l for l in pam_su if "pam_wheel.so" in l]
    results.append({
        "cis_id": "5.2.7", "title": "Ensure access to the su command is restricted",
        "status": "PASS" if wheel_su else "FAIL",
        "message": "pam_wheel.so is enforcing su restrictions." if wheel_su else "pam_wheel.so is commented out or missing.",
        "vulnerability": "Without this restriction, any local account with a known password can su to root.",
        "tier": 1
    })

    return results

def audit_l2_home_directories(passwd_data):
    """CIS 1.6: L2 Identity Controls (Root restrictions, Home directories, Dot-files)"""
    import os
    results = []

    # ---------------------------------------------------------
    # CIS 5.3.3.1.3: Ensure root is locked out for failed passwords
    # ---------------------------------------------------------
    # Dynamically load L2 config data using our global Phase 1 parser
    faillock_data = parse_key_value_config('/etc/security/faillock.conf')
    
    # If the flag is present alone on a line, our parser stores it as a key with an empty string
    even_deny_root = 'even_deny_root' in faillock_data
    
    results.append({
        "cis_id": "5.3.3.1.3",
        "title": "Ensure root account is locked for failed password attempts",
        "status": "PASS" if even_deny_root else "FAIL",
        "message": "even_deny_root is active in faillock.conf." if even_deny_root else "even_deny_root is missing.",
        "vulnerability": "Without this, root is exempt from brute-force lockout — invalidating the lockout protection entirely.",
        "tier": 2
    })

    # ---------------------------------------------------------
    # CIS 5.3.3.2.8: Ensure password quality rules apply to root
    # ---------------------------------------------------------
    pwquality_data = parse_key_value_config('/etc/security/pwquality.conf')
    enforce_for_root = 'enforce_for_root' in pwquality_data

    results.append({
        "cis_id": "5.3.3.2.8",
        "title": "Ensure password quality rules apply to root",
        "status": "PASS" if enforce_for_root else "FAIL",
        "message": "enforce_for_root is active in pwquality.conf." if enforce_for_root else "enforce_for_root is missing.",
        "vulnerability": "Root setting a weak password while users are forced to use strong ones defeats the entire policy.",
        "tier": 2
    })

    # ---------------------------------------------------------
    # CIS 7.2.9 & 7.2.10: Home Directory & Dot-File Integrity
    # ---------------------------------------------------------
    missing_homes = []
    bad_owner_homes = []
    ww_dotfiles = []
    legacy_trust_files = []

    for user, fields in passwd_data.items():
        if len(fields) >= 6:
            try:
                uid = int(fields[2])
                home = fields[5]
            except ValueError:
                continue

            # Evaluate interactive local users (UID >= 1000) excluding 'nobody'
            if uid >= 1000 and user != 'nobody':
                
                # Check 7.2.9 (Part 1): Does the directory exist?
                if not os.path.isdir(home):
                    missing_homes.append(f"{user} ({home})")
                    continue

                # Check 7.2.9 (Part 2): Is it owned by the user?
                stat_info = get_file_stat(home)
                if stat_info['exists'] and stat_info['owner'] != user:
                    bad_owner_homes.append(f"{home} (owned by {stat_info['owner']})")

                # Check 7.2.10: Scan dot-files safely
                try:
                    for filename in os.listdir(home):
                        if filename.startswith('.'):
                            filepath = os.path.join(home, filename)
                            
                            # Skip directories like . and ..
                            if not os.path.isfile(filepath):
                                continue

                            # Flag legacy insecure trust files
                            if filename in ['.netrc', '.rhosts']:
                                legacy_trust_files.append(filepath)

                            # Flag world-writable dot-files using octal logic
                            f_stat = get_file_stat(filepath)
                            if f_stat['exists']:
                                mode_int = int(f_stat['mode'], 8) # type: ignore
                                if mode_int & 0o002:  # Bitwise check for world-writable bit
                                    ww_dotfiles.append(filepath)
                except PermissionError:
                    # Gracefully skip unreadable directories
                    pass

    # Append 7.2.9 Result
    failed_729 = missing_homes or bad_owner_homes
    results.append({
        "cis_id": "7.2.9",
        "title": "Ensure all users' home directories exist and have correct ownership",
        "status": "FAIL" if failed_729 else "PASS",
        "message": f"Missing homes: {missing_homes} | Bad ownership: {bad_owner_homes}" if failed_729 else "All interactive user homes exist with correct ownership.",
        "vulnerability": "A missing or wrong-ownership home directory is a known hiding place and breaks sudo and PAM behaviour.",
        "tier": 2
    })

    # Append 7.2.10 Result
    failed_7210 = ww_dotfiles or legacy_trust_files
    results.append({
        "cis_id": "7.2.10",
        "title": "Ensure user dot-files are not world-writable and legacy trust files do not exist",
        "status": "FAIL" if failed_7210 else "PASS",
        "message": f"World-writable dot-files: {ww_dotfiles} | Legacy files (.netrc/.rhosts): {legacy_trust_files}" if failed_7210 else "All L2 dot-file checks passed.",
        "vulnerability": "World-writable .bashrc lets any user inject commands. .netrc/.rhosts are legacy insecure trust files.",
        "tier": 2
    })

    return results

# ==========================================
# 3. ORCHESTRATION & REPORTING ENGINE
# ==========================================
def main():
    all_results = []

    # 1. Load data natively into memory
    passwd_data = parse_colon_separated('/etc/passwd')
    group_data = parse_colon_separated('/etc/group')
    shadow_data = parse_colon_separated('/etc/shadow')
    #login_defs_data = parse_key_value_config('/etc/login.defs', separator='\t', ignore_equals=True)
    login_defs_data = parse_key_value_config('/etc/login.defs', ignore_equals=True)
    # 2. Execute Audits
    all_results.extend(audit_account_integrity(passwd_data, group_data, login_defs_data))
    all_results.extend(audit_shadow_hygiene(shadow_data, passwd_data))
    all_results.extend(audit_root_environment())
    all_results.extend(audit_password_aging(login_defs_data))
    all_results.extend(audit_pam_and_auth())
    all_results.extend(audit_l2_home_directories(passwd_data))

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
    output_file = "module1_report.json"
    with open(output_file, "w") as f:
        json.dump(report_data, f, indent=4)

    print(f"\n✅ Module 1 audit complete! {len(passed_or_na)} passed/N/A, {len(failed)} failed.")
    print(f"   Results written to: {os.path.abspath(output_file)}")

if __name__ == "__main__":
    main()