#!/usr/bin/env python3
"""
loki_severity_report.py
Queries Loki and prints a full breakdown of alerts per severity level,
per job source, and recent alert signatures for the last 24 hours.

Run with: python3 loki_severity_report.py
Requires: pip3 install requests
"""

import requests
import json
from datetime import datetime, timezone

LOKI_URL = "http://[your server IP Address]:[Loki Port (default port:3100)]"
LOOKBACK = 24 * 60 * 60   # 24 hours in seconds

SEVERITY_MAP = {
    "1": "Critical",
    "2": "High    ",
    "3": "Medium  ",
    "4": "Low     ",
}

# ─────────────────────────────────────────────────────────────────────

def now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def query_loki(logql, lookback_seconds=86400, limit=1000):
    """Run a LogQL range query and return all matched log entries."""
    now_ns   = int(datetime.now(timezone.utc).timestamp() * 1e9)
    start_ns = now_ns - int(lookback_seconds * 1e9)
    try:
        resp = requests.get(
            f"{LOKI_URL}/loki/api/v1/query_range",
            params={
                "query": logql,
                "start": str(start_ns),
                "end":   str(now_ns),
                "limit": str(limit),
            },
            timeout=10
        )
        if resp.status_code != 200:
            return [], f"HTTP {resp.status_code}"
        streams = resp.json().get("data", {}).get("result", [])
        entries = []
        for stream in streams:
            for ts, line in stream.get("values", []):
                entries.append((ts, line))
        return entries, None
    except Exception as e:
        return [], str(e)

def count_query(logql, lookback_seconds=86400):
    entries, err = query_loki(logql, lookback_seconds)
    return len(entries), err

def loki_ready():
    try:
        r = requests.get(f"{LOKI_URL}/ready", timeout=3)
        return r.text.strip() == "ready"
    except:
        return False

def get_labels():
    try:
        r = requests.get(f"{LOKI_URL}/loki/api/v1/labels", timeout=3)
        return r.json().get("data", [])
    except:
        return []

def bar(count, max_width=35):
    if count == 0:
        return ""
    filled = min(count, max_width)
    return "#" * filled + ("+" if count > max_width else "")

def extract_signatures(entries, limit=10):
    """Parse eve.json lines and return top alert signatures."""
    sig_counts = {}
    for _, line in entries:
        try:
            event = json.loads(line)
            if event.get("event_type") == "alert":
                sig = event.get("alert", {}).get("signature", "Unknown")
                sig_counts[sig] = sig_counts.get(sig, 0) + 1
        except:
            pass
    sorted_sigs = sorted(sig_counts.items(), key=lambda x: x[1], reverse=True)
    return sorted_sigs[:limit]

def extract_top_ips(entries, field="src_ip", limit=5):
    """Parse eve.json lines and return top source or dest IPs."""
    ip_counts = {}
    for _, line in entries:
        try:
            event = json.loads(line)
            if event.get("event_type") == "alert":
                ip = event.get(field, "unknown")
                ip_counts[ip] = ip_counts.get(ip, 0) + 1
        except:
            pass
    sorted_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)
    return sorted_ips[:limit]

# ─────────────────────────────────────────────────────────────────────

print("=" * 60)
print("  Loki Severity Report")
print(f"  {now()}  |  Last 24 hours")
print("=" * 60)

# Health check
print("\n[Status]")
up = loki_ready()
print(f"  Loki:   {'UP — ready' if up else 'DOWN — check: sudo systemctl status loki'}")
labels = get_labels()
print(f"  Labels: {labels if labels else 'none — nothing has been indexed yet'}")

if not up:
    print("\n  Loki is not running. Start it with:")
    print("  sudo systemctl start loki")
    exit(1)

# ── Suricata overview ─────────────────────────────────────────────────
print("\n── Suricata alerts (all)")
all_entries, err = query_loki('{job="suricata"}')
alert_entries = [(ts, l) for ts, l in all_entries
                 if '"event_type": "alert"' in l or '"event_type":"alert"' in l]
print(f"  Total log entries : {len(all_entries)}")
print(f"  Alert events      : {len(alert_entries)}")
if err:
    print(f"  Query error: {err}")

# ── Per severity ──────────────────────────────────────────────────────
print("\n── Suricata alerts by severity (last 24h)")
print(f"  {'SEV':<6} {'NAME':<12} {'COUNT':>6}  {'BAR'}")
print(f"  {'-'*55}")

sev_totals = {}
for sev_num, sev_name in SEVERITY_MAP.items():
    count, err = count_query(
        f'{{job="suricata", event_type="alert", severity="{sev_num}"}}'
    )
    sev_totals[sev_num] = count
    indicator = bar(count)
    err_note  = f"  (query error: {err})" if err else ""
    print(f"  SEV-{sev_num}  {sev_name}  {count:>6}  {indicator}{err_note}")

total_alerts = sum(sev_totals.values())
print(f"\n  Total categorised alerts: {total_alerts}")

# ── Top signatures ────────────────────────────────────────────────────
print("\n── Top 10 alert signatures (last 24h)")
all_alert_entries, _ = query_loki('{job="suricata", event_type="alert"}', limit=2000)
top_sigs = extract_signatures(all_alert_entries)
if top_sigs:
    for i, (sig, count) in enumerate(top_sigs, 1):
        print(f"  {i:>2}. [{count:>4}]  {sig[:65]}")
else:
    print("  No parsed signatures found — entries may not be JSON")

# ── Top source IPs ────────────────────────────────────────────────────
print("\n── Top 5 source IPs in alerts")
top_src = extract_top_ips(all_alert_entries, field="src_ip")
if top_src:
    for ip, count in top_src:
        print(f"  {count:>5}x  {ip}")
else:
    print("  No source IPs parsed")

# ── Top destination IPs ───────────────────────────────────────────────
print("\n── Top 5 destination IPs in alerts")
top_dst = extract_top_ips(all_alert_entries, field="dest_ip")
if top_dst:
    for ip, count in top_dst:
        print(f"  {count:>5}x  {ip}")
else:
    print("  No destination IPs parsed")

# ── Wazuh overview ────────────────────────────────────────────────────
print("\n── Wazuh HIDS (last 24h)")
wazuh_total, _ = count_query('{job="wazuh"}')
wazuh_high, _  = count_query('{job="wazuh"} | json | rule_level >= `10`')
wazuh_crit, _  = count_query('{job="wazuh"} | json | rule_level >= `13`')
print(f"  Total entries     : {wazuh_total}")
print(f"  High  (level>=10) : {wazuh_high}")
print(f"  Critical (>=13)   : {wazuh_crit}")

# ── Python engine ─────────────────────────────────────────────────────
print("\n── Python alert engine (last 24h)")
py_total, _ = count_query('{job="python-engine"}')
print(f"  Forwarded log lines: {py_total}")

# ── Pipeline test entries ─────────────────────────────────────────────
print("\n── Pipeline test entries (from pipeline_check.py)")
test_total, _ = count_query('{job="pipeline-test"}')
print(f"  Synthetic test entries: {test_total}")

# ── Final verdict ─────────────────────────────────────────────────────
print("\n" + "=" * 60)
print("  Verdict")
print("=" * 60)

if len(all_entries) == 0 and wazuh_total == 0 and test_total == 0:
    print("  Nothing in Loki at all.")
    print("  Run pipeline_check.py first to diagnose the chain.")
    print("  Check Alloy: sudo journalctl -u alloy -f")
elif len(alert_entries) == 0 and test_total > 0:
    print("  Direct pushes work but Suricata alerts are NOT reaching Loki.")
    print("  Problem is in Alloy not reading eve.json.")
    print("  Fix: sudo journalctl -u alloy -f")
    print("       verify __path__ in /etc/alloy/config.alloy")
elif len(alert_entries) > 0:
    print(f"  Pipeline is healthy — {len(alert_entries)} Suricata alerts in Loki.")
    print(f"  Open Grafana at http://<server-ip>:3000 to view dashboards.")
else:
    print("  Some data present but Suricata alerts missing.")
    print("  Run: sudo python3 severity_trigger.py to generate test traffic.")
