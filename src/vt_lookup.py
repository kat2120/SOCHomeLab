#!/usr/bin/env python3
"""VirusTotal IP reputation lookup."""

import os
import requests

VT_API_KEY = "[INPUT YOUR VIRUSTOTAL API]"
VT_URL     = "https://www.virustotal.com/api/v3/ip_addresses/{}"
def check_ip_reputation(ip):
    if not VT_API_KEY:
        return None
    try:
        response = requests.get(
            VT_URL.format(ip),
            headers={"x-apikey": VT_API_KEY},
            timeout=5,
        )
        if response.status_code != 200:
            return None
        stats     = response.json()["data"]["attributes"]["last_analysis_stats"]
        malicious = stats.get("malicious", 0)
        total     = sum(stats.values())
        return {"ip": ip, "malicious": malicious, "total": total, "score": f"{malicious}/{total}"}
    except Exception:
        return None
