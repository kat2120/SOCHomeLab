#!/usr/bin/env python3
"""
HomeSOC Alert Engine
Tails Suricata eve.json and forwards critical alerts to Telegram.
"""
import json
import time
import os
from datetime import datetime
from vt_lookup import check_ip_reputation
from telegram_bot import send_alert


EVE_LOG     = "/var/log/suricata/eve.json"
MIN_SEV     = int("2")   # 1=critical, 2=high, 3=medium, 4=low

def now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def tail_file(filepath):
    """Tail a file and yield new lines as they appear."""
    while not os.path.exists(filepath):
        print(f"[{now()}] Waiting for {filepath}...")
        time.sleep(5)
    with open(filepath, "r") as f:
        f.seek(0, 2)
        current_inode = os.fstat(f.fileno()).st_ino
        while True:
            line = f.readline()
            if line:
                yield line.strip()
            else:
                time.sleep(0.5)
                try:
                    if os.stat(filepath).st_ino != current_inode:
                        f = open(filepath, "r")
                        current_inode = os.stat(filepath).st_ino
                except FileNotFoundError:
                    pass

def parse_alert(line):
    try:
        return json.loads(line)
    except json.JSONDecodeError:
        return None

def process_alert(event):
    if event.get("event_type") != "alert":
        return None

    alert    = event.get("alert", {})
    severity = alert.get("severity", 99)

    if severity > MIN_SEV:
        return None

    src_ip    = event.get("src_ip",   "unknown")
    dest_ip   = event.get("dest_ip",  "unknown")
    proto     = event.get("proto",    "unknown")
    signature = alert.get("signature",    "Unknown rule")
    category  = alert.get("category",     "Uncategorized")
    sid       = alert.get("signature_id", "?")
    timestamp = event.get("timestamp", now())

    vt_result = None
    if src_ip and not src_ip.startswith(("192.168.", "10.", "172.")):
        vt_result = check_ip_reputation(src_ip)

    return {
        "severity":  severity,
        "signature": signature,
        "category":  category,
        "sid":       sid,
        "src_ip":    src_ip,
        "dest_ip":   dest_ip,
        "proto":     proto,
        "timestamp": timestamp,
        "vt_result": vt_result,
    }

def main():
    print(f"[{now()}] HomeSOC Alert Engine started")
    print(f"[{now()}] Watching: {EVE_LOG}")
    print(f"[{now()}] Min severity: {MIN_SEV}")

    for line in tail_file(EVE_LOG):
        event = parse_alert(line)
        if not event:
            continue
        processed = process_alert(event)
        if not processed:
            continue
        print(f"[{now()}] ALERT SEV-{processed['severity']} — {processed['signature']}")
        send_alert(processed)

if __name__ == "__main__":
    main()
