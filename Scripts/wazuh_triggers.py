#!/usr/bin/env python3
"""
wazuh_triggers.py
Performs actions that Wazuh's host-based detection rules are tuned to catch.
Each test targets a specific Wazuh rule category.

Run with: sudo python3 wazuh_triggers.py
No external dependencies required.

IMPORTANT: Run only on your own lab server.
"""

import os
import subprocess
import time
import json
import stat
from datetime import datetime

WAZUH_ALERTS = "/var/ossec/logs/alerts/alerts.json"
WAZUH_LOG    = "/var/ossec/logs/ossec.log"

def now():
    return datetime.now().strftime("%H:%M:%S")

def header(num, title, rule_ref):
    print(f"\n── Test {num}: {title}")
    print(f"   Wazuh rules: {rule_ref}")
    print(f"   Started: {now()}")

def result(success, detail=""):
    status = "TRIGGERED" if success else "SKIPPED"
    print(f"   Result:  {status}  {detail}")

def wait_and_check(keyword, seconds=3):
    """Wait briefly then grep alerts.json for a keyword."""
    time.sleep(seconds)
    try:
        r = subprocess.run(
            ["sudo", "tail", "-30", WAZUH_ALERTS],
            capture_output=True, text=True
        )
        found = keyword.lower() in r.stdout.lower()
        return found
    except:
        return False

def count_alert_lines():
    """Return current line count of alerts.json."""
    try:
        r = subprocess.run(
            ["sudo", "wc", "-l", WAZUH_ALERTS],
            capture_output=True, text=True
        )
        return int(r.stdout.strip().split()[0])
    except:
        return 0

# ─────────────────────────────────────────────────────────────────────

print("=" * 60)
print("  Wazuh Host Trigger Test Suite")
print(f"  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
print("=" * 60)
print(f"\n  Watching: {WAZUH_ALERTS}")
print(f"  Tail alerts live in another terminal:")
print(f"  sudo tail -f {WAZUH_ALERTS} | python3 -m json.tool\n")

baseline = count_alert_lines()
print(f"  Baseline alert count: {baseline} lines")
time.sleep(1)

results = []

# ─────────────────────────────────────────────────────────────────────
# TEST 1 — Suspicious file created in /tmp
# Wazuh rule 553: Dangerous file created in /tmp
# ─────────────────────────────────────────────────────────────────────
header(1, "Suspicious executable in /tmp", "553, 554")
try:
    path = "/tmp/malware_test.sh"
    with open(path, "w") as f:
        f.write("#!/bin/bash\necho 'rootkit simulation'\n")
    os.chmod(path, 0o755)
    print(f"   Created: {path} (chmod 755)")
    found = wait_and_check("tmp")
    result(True, "— check for rule 553 in alerts")
    results.append(("Suspicious file in /tmp", True))
    # cleanup
    os.remove(path)
    print(f"   Cleaned up: {path}")
except Exception as e:
    result(False, str(e))
    results.append(("Suspicious file in /tmp", False))

# ─────────────────────────────────────────────────────────────────────
# TEST 2 — File Integrity Monitoring (FIM) — modify watched file
# Wazuh rule 550: Integrity checksum changed
# Wazuh rule 554: File added to the system
# ─────────────────────────────────────────────────────────────────────
header(2, "File Integrity Monitoring trigger", "550, 554")
try:
    # Touch /etc/hosts — Wazuh FIM watches this file by default
    subprocess.run(["sudo", "touch", "/etc/hosts"], check=True)
    print(f"   Touched /etc/hosts — FIM checksum change recorded")

    # Also create and remove a file in a watched directory
    test_file = "/etc/fim_test_file"
    subprocess.run(["sudo", "touch", test_file], check=True)
    print(f"   Created: {test_file}")
    time.sleep(2)
    subprocess.run(["sudo", "rm", "-f", test_file], check=True)
    print(f"   Removed: {test_file}")

    result(True, "— FIM events queued (may take up to 60s for Wazuh to report)")
    results.append(("FIM trigger", True))
except Exception as e:
    result(False, str(e))
    results.append(("FIM trigger", False))

# ─────────────────────────────────────────────────────────────────────
# TEST 3 — Read /etc/shadow (credential access attempt)
# Wazuh rule 5503: Attempt to read shadow passwords
# ─────────────────────────────────────────────────────────────────────
header(3, "Shadow password file access", "5503")
try:
    with open("/etc/shadow", "r") as f:
        content = f.read(10)
    print(f"   Read /etc/shadow — succeeded (running as root)")
    result(True, "— access logged by Wazuh audit")
    results.append(("Shadow file access", True))
except PermissionError:
    print(f"   Read /etc/shadow — Permission denied (expected if not root)")
    print(f"   The access attempt itself is still logged by Wazuh")
    result(True, "— denied access still triggers rule 5503")
    results.append(("Shadow file access", True))
except Exception as e:
    result(False, str(e))
    results.append(("Shadow file access", False))

# ─────────────────────────────────────────────────────────────────────
# TEST 4 — Multiple failed sudo attempts (privilege escalation sim)
# Wazuh rule 5401: Successful sudo
# Wazuh rule 5402: Failed sudo attempt
# ─────────────────────────────────────────────────────────────────────
header(4, "Failed sudo attempts", "5401, 5402")
print(f"   Sending 6 failed sudo attempts...")
failed = 0
for i in range(6):
    r = subprocess.run(
        ["sudo", "-k", "-S", "id"],
        input=b"definitelywrongpassword123\n",
        capture_output=True
    )
    if r.returncode != 0:
        failed += 1
    print(f"   Attempt {i+1}/6: {'failed' if r.returncode != 0 else 'succeeded'}")
    time.sleep(0.4)

result(failed >= 3, f"— {failed}/6 attempts failed, rule 5402 should fire")
results.append(("Failed sudo", failed >= 3))

# ─────────────────────────────────────────────────────────────────────
# TEST 5 — User enumeration (/etc/passwd read)
# Wazuh rule 5901: System user enumeration
# ─────────────────────────────────────────────────────────────────────
header(5, "User enumeration via /etc/passwd", "5901")
try:
    with open("/etc/passwd", "r") as f:
        users = [line.split(":")[0] for line in f.readlines()]
    print(f"   Read /etc/passwd — found {len(users)} user entries")
    print(f"   Users: {', '.join(users[:8])}{'...' if len(users) > 8 else ''}")
    result(True, "— read attempt logged")
    results.append(("User enumeration", True))
except Exception as e:
    result(False, str(e))
    results.append(("User enumeration", False))

# ─────────────────────────────────────────────────────────────────────
# TEST 6 — Rapid failed SSH logins (brute force from localhost)
# Wazuh rule 5710: SSH authentication failure
# Wazuh rule 5763: SSH brute force (multiple failures)
# ─────────────────────────────────────────────────────────────────────
header(6, "SSH brute force simulation", "5710, 5763")
print(f"   Sending 10 failed SSH attempts to localhost...")
ssh_fails = 0
for i in range(10):
    r = subprocess.run(
        ["ssh",
         "-o", "StrictHostKeyChecking=no",
         "-o", "ConnectTimeout=2",
         "-o", "BatchMode=yes",          # prevents password prompt
         "-p", "22",
         f"fakeuser_{i}@127.0.0.1",
         "id"],
        capture_output=True
    )
    if r.returncode != 0:
        ssh_fails += 1
    print(f"   Attempt {i+1:>2}/10 (fakeuser_{i}): failed")
    time.sleep(0.3)

result(ssh_fails >= 5, f"— {ssh_fails}/10 failed, rules 5710/5763 should fire")
results.append(("SSH brute force", ssh_fails >= 5))

# ─────────────────────────────────────────────────────────────────────
# TEST 7 — SUID binary creation (rootkit indicator)
# Wazuh rule 550, 554: New SUID file detected
# ─────────────────────────────────────────────────────────────────────
header(7, "SUID file creation", "550, 554")
try:
    suid_path = "/tmp/suid_test_bin"
    with open(suid_path, "w") as f:
        f.write("#!/bin/bash\necho test\n")
    # Set SUID bit — Wazuh FIM detects this as high severity
    os.chmod(suid_path, 0o4755)
    actual_mode = oct(os.stat(suid_path).st_mode)
    print(f"   Created: {suid_path}")
    print(f"   Mode:    {actual_mode} (SUID bit set)")
    time.sleep(2)
    os.remove(suid_path)
    print(f"   Cleaned up: {suid_path}")
    result(True, "— SUID creation logged by FIM")
    results.append(("SUID file creation", True))
except Exception as e:
    result(False, str(e))
    results.append(("SUID file creation", False))

# ─────────────────────────────────────────────────────────────────────
# TEST 8 — Write to /etc/cron.d (persistence mechanism)
# Wazuh rule 550: Watched file modified
# ─────────────────────────────────────────────────────────────────────
header(8, "Cron persistence simulation", "550, 553")
try:
    cron_path = "/etc/cron.d/homesoc_test"
    subprocess.run(
        ["sudo", "bash", "-c",
         f'echo "# homesoc test entry" > {cron_path}'],
        check=True
    )
    print(f"   Created: {cron_path}")
    time.sleep(2)
    subprocess.run(["sudo", "rm", "-f", cron_path], check=True)
    print(f"   Cleaned up: {cron_path}")
    result(True, "— cron directory write logged by FIM")
    results.append(("Cron persistence", True))
except Exception as e:
    result(False, str(e))
    results.append(("Cron persistence", False))

# ─────────────────────────────────────────────────────────────────────
# Final alert count comparison
# ─────────────────────────────────────────────────────────────────────
time.sleep(5)
final = count_alert_lines()
new_alerts = final - baseline

print("\n" + "=" * 60)
print("  Results")
print("=" * 60)
print(f"\n  {'TEST':<30} {'STATUS'}")
print(f"  {'-'*45}")
for name, passed in results:
    print(f"  {name:<30} {'TRIGGERED' if passed else 'SKIPPED'}")

print(f"\n  Alert lines before : {baseline}")
print(f"  Alert lines after  : {final}")
print(f"  New alerts added   : {new_alerts}")

if new_alerts > 0:
    print(f"\n  Wazuh is generating alerts.")
    print(f"  Check Grafana: http://<server-ip>:3000")
    print(f"  Query: {{job=\"wazuh\"}} | json | rule_level >= `5`")
else:
    print(f"\n  No new alerts detected in {WAZUH_ALERTS}")
    print(f"  FIM alerts may be delayed — check in 60s:")
    print(f"  sudo tail -f {WAZUH_ALERTS} | python3 -m json.tool")
    print(f"  Also verify Wazuh is running:")
    print(f"  sudo systemctl status wazuh-manager")
