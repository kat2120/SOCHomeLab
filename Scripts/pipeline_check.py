#!/usr/bin/env python3
"""
pipeline_check.py
Fires a test alert for each severity level then queries Loki to confirm
receipt at each stage: Suricata → Loki → Grafana-ready.

Run with: sudo python3 pipeline_check.py
Requires: pip3 install requests
"""

import socket
import time
import json
import subprocess
import requests
from datetime import datetime, timezone

LOKI_URL  = "http://localhost:[Loki Port (default port: 3100)]"
TARGET_IP = "127.0.0.1"
WAIT_TIME = 8   # seconds to wait after trigger before checking Loki

# ─────────────────────────────────────────────────────────────────────

def now():
    return datetime.now().strftime("%H:%M:%S")

def send_tcp(ip, port, payload=b"test"):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        s.connect((ip, port))
        s.send(payload)
        s.close()
    except:
        pass

def check_suricata_fast_log(keyword):
    """Check if keyword appeared in the last 50 lines of fast.log."""
    try:
        result = subprocess.run(
            ["sudo", "tail", "-50", "/var/log/suricata/fast.log"],
            capture_output=True, text=True
        )
        lines   = result.stdout.strip().split("\n")
        matches = [l for l in lines if keyword.lower() in l.lower()]
        return len(matches) > 0, matches[-1] if matches else ""
    except Exception as e:
        return False, str(e)

def check_suricata_eve_log(keyword):
    """Check eve.json for keyword in the last 30 lines as a fallback."""
    try:
        result = subprocess.run(
            ["sudo", "tail", "-30", "/var/log/suricata/eve.json"],
            capture_output=True, text=True
        )
        lines   = result.stdout.strip().split("\n")
        matches = [l for l in lines if keyword.lower() in l.lower()]
        return len(matches) > 0, matches[-1][:100] if matches else ""
    except Exception as e:
        return False, str(e)

def check_loki(job="suricata", lookback_seconds=120):
    """Query Loki for recent entries from the given job label."""
    try:
        now_ns   = int(datetime.now(timezone.utc).timestamp() * 1e9)
        start_ns = now_ns - int(lookback_seconds * 1e9)
        params   = {
            "query": f'{{job="{job}"}}',
            "start": str(start_ns),
            "end":   str(now_ns),
            "limit": "10",
        }
        resp    = requests.get(
            f"{LOKI_URL}/loki/api/v1/query_range",
            params=params, timeout=5
        )
        data    = resp.json()
        streams = data.get("data", {}).get("result", [])
        total   = sum(len(s.get("values", [])) for s in streams)
        return total > 0, total
    except Exception as e:
        return False, str(e)

def check_loki_labels():
    """Return list of label names Loki has indexed so far."""
    try:
        resp = requests.get(f"{LOKI_URL}/loki/api/v1/labels", timeout=5)
        return resp.json().get("data", [])
    except:
        return []

def push_synthetic_log(severity):
    """Push a fake log line directly to Loki to verify ingest works."""
    now_ns  = str(int(datetime.now(timezone.utc).timestamp() * 1e9))
    payload = {
        "streams": [{
            "stream": {
                "job":      "pipeline-test",
                "severity": str(severity),
                "source":   "pipeline_check"
            },
            "values": [[now_ns, json.dumps({
                "event_type": "alert",
                "severity":   severity,
                "message":    f"Synthetic pipeline test — severity {severity}",
                "timestamp":  datetime.now().isoformat()
            })]]
        }]
    }
    try:
        resp = requests.post(
            f"{LOKI_URL}/loki/api/v1/push",
            json=payload, timeout=5
        )
        return resp.status_code == 204
    except Exception as e:
        return False

# ─────────────────────────────────────────────────────────────────────

SEVERITY_TESTS = [
    {
        "severity":    1,
        "label":       "CRITICAL",
        "description": "Meterpreter user agent",
        "trigger": lambda: send_tcp(TARGET_IP, 80,
            b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n"
            b"User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Meterpreter)\r\n"
            b"Connection: close\r\n\r\n"),
        "fast_log_kw": "MALWARE",
        "eve_kw":      "alert",
    },
    {
        "severity":    2,
        "label":       "HIGH",
        "description": "SQL injection payload",
        "trigger": lambda: send_tcp(TARGET_IP, 80,
            b"GET /?id=1'%20UNION%20SELECT%201,2,3-- HTTP/1.1\r\n"
            b"Host: 127.0.0.1\r\nUser-Agent: Mozilla/5.0\r\n"
            b"Connection: close\r\n\r\n"),
        "fast_log_kw": "SQL",
        "eve_kw":      "alert",
    },
    {
        "severity":    3,
        "label":       "MEDIUM",
        "description": "Nmap scripting engine UA",
        "trigger": lambda: send_tcp(TARGET_IP, 80,
            b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n"
            b"User-Agent: Mozilla/5.0 (Nmap Scripting Engine)\r\n"
            b"Connection: close\r\n\r\n"),
        "fast_log_kw": "SCAN",
        "eve_kw":      "alert",
    },
    {
        "severity":    4,
        "label":       "LOW",
        "description": "curl user agent",
        "trigger": lambda: send_tcp(TARGET_IP, 80,
            b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n"
            b"User-Agent: curl/7.88.1\r\n"
            b"Connection: close\r\n\r\n"),
        "fast_log_kw": "curl",
        "eve_kw":      "alert",
    },
]

# ─────────────────────────────────────────────────────────────────────

print("=" * 65)
print("  Pipeline Check — Suricata → Loki → Grafana")
print(f"  Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
print("=" * 65)

# ── Pre-flight: Loki health ───────────────────────────────────────────
print("\n[Pre-flight] Loki health check...")
try:
    r = requests.get(f"{LOKI_URL}/ready", timeout=3)
    loki_up = r.text.strip() == "ready"
    print(f"  Loki:   {'UP — ready' if loki_up else 'NOT READY: ' + r.text}")
except Exception as e:
    loki_up = False
    print(f"  Loki:   DOWN — {e}")

labels = check_loki_labels()
print(f"  Labels: {labels if labels else 'none indexed yet'}")

# ── Pre-flight: synthetic direct push ────────────────────────────────
print("\n[Pre-flight] Pushing synthetic logs directly to Loki...")
for sev in [1, 2, 3, 4]:
    ok = push_synthetic_log(sev)
    print(f"  Severity {sev} direct push: {'OK' if ok else 'FAILED — Loki may be down'}")

print(f"\n  Waiting {WAIT_TIME}s for Loki to index...")
time.sleep(WAIT_TIME)

labels_after = check_loki_labels()
has_test = "pipeline-test" in labels_after
print(f"  Direct push verified: {'YES — pipeline-test label found' if has_test else 'NO — check Loki storage config'}")

# ── Per-severity tests ────────────────────────────────────────────────
print("\n" + "=" * 65)
print("  Severity Level Tests")
print("=" * 65)

results = []

for test in SEVERITY_TESTS:
    sev   = test["severity"]
    label = test["label"]
    desc  = test["description"]

    print(f"\n── SEV-{sev} {label} — {desc}")

    # Stage 1: fire the network trigger
    print(f"  [1/3] Firing trigger...", end=" ", flush=True)
    test["trigger"]()
    print(f"sent — waiting {WAIT_TIME}s")
    time.sleep(WAIT_TIME)

    # Stage 2: check Suricata fast.log
    print(f"  [2/3] Suricata fast.log...", end=" ", flush=True)
    sur_hit, sur_line = check_suricata_fast_log(test["fast_log_kw"])
    if not sur_hit:
        # fallback: check eve.json directly
        sur_hit, sur_line = check_suricata_eve_log(test["eve_kw"])
    if sur_hit:
        print(f"FOUND")
        print(f"         {sur_line[:90]}")
    else:
        print(f"NOT FOUND  (keyword: {test['fast_log_kw']})")
        print(f"         Rule may not be in your ruleset or traffic didn't match")

    # Stage 3: check Loki received it
    print(f"  [3/3] Loki (job=suricata)...", end=" ", flush=True)
    loki_hit, loki_count = check_loki(job="suricata", lookback_seconds=180)
    if loki_hit:
        print(f"FOUND ({loki_count} entries in last 3 min)")
    else:
        print(f"NOT FOUND")
        print(f"         Check Alloy: sudo journalctl -u alloy -n 20 --no-pager")

    stage = "FULL PASS" if (sur_hit and loki_hit) else \
            "PARTIAL  " if sur_hit else \
            "NO ALERT "
    results.append((sev, label, desc, sur_hit, loki_hit, stage))

# ── Summary ───────────────────────────────────────────────────────────
print("\n" + "=" * 65)
print("  Summary")
print("=" * 65)
print(f"  {'SEV':<5} {'LABEL':<10} {'SURICATA':<12} {'LOKI':<10} STATUS")
print(f"  {'-'*60}")
for sev, label, desc, sur, lok, stage in results:
    print(f"  {sev:<5} {label:<10} {'PASS' if sur else 'FAIL':<12} {'PASS' if lok else 'FAIL':<10} {stage}")

print("\n  Diagnosis:")
all_sur  = all(r[3] for r in results)
all_loki = all(r[4] for r in results)
none_sur = not any(r[3] for r in results)

if all_sur and all_loki:
    print("  All stages passing — pipeline is fully operational.")
elif all_sur and not all_loki:
    print("  Suricata is firing but Loki is NOT receiving logs.")
    print("  Fix: sudo journalctl -u alloy -f")
    print("       verify __path__ in /etc/alloy/config.alloy")
    print("       sudo systemctl restart alloy")
elif none_sur:
    print("  Suricata is not generating any alerts.")
    print("  Fix: sudo suricata-update && sudo systemctl restart suricata")
    print("       check interface in /etc/suricata/suricata.yaml")
else:
    print("  Partial — some severity levels not triggering.")
    print("  Some rules may not be in your current ruleset.")
    print("  Run: sudo suricata-update to refresh rules.")#!/usr/bin/env python3
"""
pipeline_check.py
Fires a test alert for each severity level then queries Loki to confirm
receipt at each stage: Suricata → Loki → Grafana-ready.

Run with: sudo python3 pipeline_check.py
Requires: pip3 install requests
"""

import socket
import time
import json
import subprocess
import requests
from datetime import datetime, timezone

LOKI_URL  = "http://192.168.1.33:3100"
TARGET_IP = "192.168.1.33"
WAIT_TIME = 8   # seconds to wait after trigger before checking Loki

# ─────────────────────────────────────────────────────────────────────

def now():
    return datetime.now().strftime("%H:%M:%S")

def send_tcp(ip, port, payload=b"test"):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        s.connect((ip, port))
        s.send(payload)
        s.close()
    except:
        pass

def check_suricata_fast_log(keyword):
    """Check if keyword appeared in the last 50 lines of fast.log."""
    try:
        result = subprocess.run(
            ["sudo", "tail", "-50", "/var/log/suricata/fast.log"],
            capture_output=True, text=True
        )
        lines   = result.stdout.strip().split("\n")
        matches = [l for l in lines if keyword.lower() in l.lower()]
        return len(matches) > 0, matches[-1] if matches else ""
    except Exception as e:
        return False, str(e)

def check_suricata_eve_log(keyword):
    """Check eve.json for keyword in the last 30 lines as a fallback."""
    try:
        result = subprocess.run(
            ["sudo", "tail", "-30", "/var/log/suricata/eve.json"],
            capture_output=True, text=True
        )
        lines   = result.stdout.strip().split("\n")
        matches = [l for l in lines if keyword.lower() in l.lower()]
        return len(matches) > 0, matches[-1][:100] if matches else ""
    except Exception as e:
        return False, str(e)

def check_loki(job="suricata", lookback_seconds=120):
    """Query Loki for recent entries from the given job label."""
    try:
        now_ns   = int(datetime.now(timezone.utc).timestamp() * 1e9)
        start_ns = now_ns - int(lookback_seconds * 1e9)
        params   = {
            "query": f'{{job="{job}"}}',
            "start": str(start_ns),
            "end":   str(now_ns),
            "limit": "10",
        }
        resp    = requests.get(
            f"{LOKI_URL}/loki/api/v1/query_range",
            params=params, timeout=5
        )
        data    = resp.json()
        streams = data.get("data", {}).get("result", [])
        total   = sum(len(s.get("values", [])) for s in streams)
        return total > 0, total
    except Exception as e:
        return False, str(e)

def check_loki_labels():
    """Return list of label names Loki has indexed so far."""
    try:
        resp = requests.get(f"{LOKI_URL}/loki/api/v1/labels", timeout=5)
        return resp.json().get("data", [])
    except:
        return []

def push_synthetic_log(severity):
    """Push a fake log line directly to Loki to verify ingest works."""
    now_ns  = str(int(datetime.now(timezone.utc).timestamp() * 1e9))
    payload = {
        "streams": [{
            "stream": {
                "job":      "pipeline-test",
                "severity": str(severity),
                "source":   "pipeline_check"
            },
            "values": [[now_ns, json.dumps({
                "event_type": "alert",
                "severity":   severity,
                "message":    f"Synthetic pipeline test — severity {severity}",
                "timestamp":  datetime.now().isoformat()
            })]]
        }]
    }
    try:
        resp = requests.post(
            f"{LOKI_URL}/loki/api/v1/push",
            json=payload, timeout=5
        )
        return resp.status_code == 204
    except Exception as e:
        return False

# ─────────────────────────────────────────────────────────────────────

SEVERITY_TESTS = [
    {
        "severity":    1,
        "label":       "CRITICAL",
        "description": "Meterpreter user agent",
        "trigger": lambda: send_tcp(TARGET_IP, 80,
            b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n"
            b"User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Meterpreter)\r\n"
            b"Connection: close\r\n\r\n"),
        "fast_log_kw": "MALWARE",
        "eve_kw":      "alert",
    },
    {
        "severity":    2,
        "label":       "HIGH",
        "description": "SQL injection payload",
        "trigger": lambda: send_tcp(TARGET_IP, 80,
            b"GET /?id=1'%20UNION%20SELECT%201,2,3-- HTTP/1.1\r\n"
            b"Host: 127.0.0.1\r\nUser-Agent: Mozilla/5.0\r\n"
            b"Connection: close\r\n\r\n"),
        "fast_log_kw": "SQL",
        "eve_kw":      "alert",
    },
    {
        "severity":    3,
        "label":       "MEDIUM",
        "description": "Nmap scripting engine UA",
        "trigger": lambda: send_tcp(TARGET_IP, 80,
            b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n"
            b"User-Agent: Mozilla/5.0 (Nmap Scripting Engine)\r\n"
            b"Connection: close\r\n\r\n"),
        "fast_log_kw": "SCAN",
        "eve_kw":      "alert",
    },
    {
        "severity":    4,
        "label":       "LOW",
        "description": "curl user agent",
        "trigger": lambda: send_tcp(TARGET_IP, 80,
            b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n"
            b"User-Agent: curl/7.88.1\r\n"
            b"Connection: close\r\n\r\n"),
        "fast_log_kw": "curl",
        "eve_kw":      "alert",
    },
]

# ─────────────────────────────────────────────────────────────────────

print("=" * 65)
print("  Pipeline Check — Suricata → Loki → Grafana")
print(f"  Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
print("=" * 65)

# ── Pre-flight: Loki health ───────────────────────────────────────────
print("\n[Pre-flight] Loki health check...")
try:
    r = requests.get(f"{LOKI_URL}/ready", timeout=3)
    loki_up = r.text.strip() == "ready"
    print(f"  Loki:   {'UP — ready' if loki_up else 'NOT READY: ' + r.text}")
except Exception as e:
    loki_up = False
    print(f"  Loki:   DOWN — {e}")

labels = check_loki_labels()
print(f"  Labels: {labels if labels else 'none indexed yet'}")

# ── Pre-flight: synthetic direct push ────────────────────────────────
print("\n[Pre-flight] Pushing synthetic logs directly to Loki...")
for sev in [1, 2, 3, 4]:
    ok = push_synthetic_log(sev)
    print(f"  Severity {sev} direct push: {'OK' if ok else 'FAILED — Loki may be down'}")

print(f"\n  Waiting {WAIT_TIME}s for Loki to index...")
time.sleep(WAIT_TIME)

labels_after = check_loki_labels()
has_test = "pipeline-test" in labels_after
print(f"  Direct push verified: {'YES — pipeline-test label found' if has_test else 'NO — check Loki storage config'}")

# ── Per-severity tests ────────────────────────────────────────────────
print("\n" + "=" * 65)
print("  Severity Level Tests")
print("=" * 65)

results = []

for test in SEVERITY_TESTS:
    sev   = test["severity"]
    label = test["label"]
    desc  = test["description"]

    print(f"\n── SEV-{sev} {label} — {desc}")

    # Stage 1: fire the network trigger
    print(f"  [1/3] Firing trigger...", end=" ", flush=True)
    test["trigger"]()
    print(f"sent — waiting {WAIT_TIME}s")
    time.sleep(WAIT_TIME)

    # Stage 2: check Suricata fast.log
    print(f"  [2/3] Suricata fast.log...", end=" ", flush=True)
    sur_hit, sur_line = check_suricata_fast_log(test["fast_log_kw"])
    if not sur_hit:
        # fallback: check eve.json directly
        sur_hit, sur_line = check_suricata_eve_log(test["eve_kw"])
    if sur_hit:
        print(f"FOUND")
        print(f"         {sur_line[:90]}")
    else:
        print(f"NOT FOUND  (keyword: {test['fast_log_kw']})")
        print(f"         Rule may not be in your ruleset or traffic didn't match")

    # Stage 3: check Loki received it
    print(f"  [3/3] Loki (job=suricata)...", end=" ", flush=True)
    loki_hit, loki_count = check_loki(job="suricata", lookback_seconds=180)
    if loki_hit:
        print(f"FOUND ({loki_count} entries in last 3 min)")
    else:
        print(f"NOT FOUND")
        print(f"         Check Alloy: sudo journalctl -u alloy -n 20 --no-pager")

    stage = "FULL PASS" if (sur_hit and loki_hit) else \
            "PARTIAL  " if sur_hit else \
            "NO ALERT "
    results.append((sev, label, desc, sur_hit, loki_hit, stage))

# ── Summary ───────────────────────────────────────────────────────────
print("\n" + "=" * 65)
print("  Summary")
print("=" * 65)
print(f"  {'SEV':<5} {'LABEL':<10} {'SURICATA':<12} {'LOKI':<10} STATUS")
print(f"  {'-'*60}")
for sev, label, desc, sur, lok, stage in results:
    print(f"  {sev:<5} {label:<10} {'PASS' if sur else 'FAIL':<12} {'PASS' if lok else 'FAIL':<10} {stage}")

print("\n  Diagnosis:")
all_sur  = all(r[3] for r in results)
all_loki = all(r[4] for r in results)
none_sur = not any(r[3] for r in results)

if all_sur and all_loki:
    print("  All stages passing — pipeline is fully operational.")
elif all_sur and not all_loki:
    print("  Suricata is firing but Loki is NOT receiving logs.")
    print("  Fix: sudo journalctl -u alloy -f")
    print("       verify __path__ in /etc/alloy/config.alloy")
    print("       sudo systemctl restart alloy")
elif none_sur:
    print("  Suricata is not generating any alerts.")
    print("  Fix: sudo suricata-update && sudo systemctl restart suricata")
    print("       check interface in /etc/suricata/suricata.yaml")
else:
    print("  Partial — some severity levels not triggering.")
    print("  Some rules may not be in your current ruleset.")
    print("  Run: sudo suricata-update to refresh rules.")
