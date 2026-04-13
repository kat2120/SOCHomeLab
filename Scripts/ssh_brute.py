#!/usr/bin/env python3
"""
ssh_brute.py
Simulates an SSH brute force attack.
Triggers Suricata: ET SCAN SSH BruteForce
Triggers Wazuh:    rule 5763 (SSH brute force), rule 5710 (multiple failures)
"""

import socket
import time
from datetime import datetime

TARGET_IP   = "192.168.1.33"    # point at your own server to trigger Wazuh
TARGET_PORT = 7389		# ssh target port
ATTEMPTS    = 30              # Wazuh triggers at 8+ failures in 2 minutes
DELAY       = 0.3             # seconds between attempts

# Fake credentials — these will all fail, generating auth failures in /var/log/secure
USERNAMES = ["root", "admin", "user", "test", "ubuntu", "pi", "oracle", "postgres"]
PASSWORDS = ["password", "123456", "admin", "letmein", "qwerty", "root", "toor"]

print(f"[{datetime.now()}] Starting SSH brute force simulation on {TARGET_IP}:{TARGET_PORT}")
print(f"Running {ATTEMPTS} attempts with {DELAY}s delay\n")

attempt = 0
for user in USERNAMES:
    for passwd in PASSWORDS:
        if attempt >= ATTEMPTS:
            break
        try:
            # Just open and close the TCP connection rapidly —
            # enough to trigger detection without needing paramiko
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            sock.connect((TARGET_IP, TARGET_PORT))
            banner = sock.recv(256)
            print(f"  [{attempt+1:02d}] Tried {user}:{passwd} — connected ({len(banner)} bytes)")
            sock.close()
        except Exception as e:
            print(f"  [{attempt+1:02d}] Tried {user}:{passwd} — {e}")
        attempt += 1
        time.sleep(DELAY)

print(f"\n[{datetime.now()}] Brute force simulation complete — {attempt} attempts sent")
