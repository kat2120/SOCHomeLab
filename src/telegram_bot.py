#!/usr/bin/env python3
"""Telegram notification sender."""

import os
import requests

BOT_TOKEN = "[INPUT YOUR BOT TOKEN]"
CHAT_ID   = "[INPUT YOUR CHAT ID]"
API_URL   = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"

SEVERITY_LABELS = {1: "CRITICAL", 2: "HIGH", 3: "MEDIUM", 4: "LOW"}

def format_message(alert):
    sev_label = SEVERITY_LABELS.get(alert["severity"], "UNKNOWN")
    lines = [
        f"<b>Suricata Alert — {sev_label}</b>",
        f"",
        f"<b>Rule:</b> <code>{alert['signature']}</code>",
        f"<b>Category:</b> {alert['category']}",
        f"<b>SID:</b> {alert['sid']}",
        f"",
        f"<b>Source:</b>      <code>{alert['src_ip']}</code>",
        f"<b>Destination:</b> <code>{alert['dest_ip']}</code>",
        f"<b>Protocol:</b>    {alert['proto']}",
        f"",
        f"<b>Time:</b> {alert['timestamp']}",
    ]
    if alert.get("vt_result"):
        vt = alert["vt_result"]
        lines.append(f"<b>VirusTotal:</b> {vt['score']} engines flagged")
    return "\n".join(lines)

def send_alert(alert):
    if not BOT_TOKEN or not CHAT_ID:
        print("Telegram not configured — skipping")
        return
    try:
        requests.post(API_URL, json={
            "chat_id":    CHAT_ID,
            "text":       format_message(alert),
            "parse_mode": "HTML",
        }, timeout=10)
    except Exception as e:
        print(f"Telegram send failed: {e}")
