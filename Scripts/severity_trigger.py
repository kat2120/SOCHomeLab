
#!/usr/bin/env python3
"""
severity_trigger.py
Generates traffic designed to trigger Suricata alerts at each severity level.
Severity 1 = Critical, 2 = High, 3 = Medium, 4 = Low/Info
"""

import socket
import time
import subprocess
import os
from datetime import datetime

TARGET_IP   = "[Your Server IP Address]"
DELAY       = 0.5

def log(severity, label, message):
    timestamp = datetime.now().strftime("%H:%M:%S")
    bar = {1: "CRITICAL", 2: "HIGH    ", 3: "MEDIUM  ", 4: "LOW     "}
    print(f"[{timestamp}] SEV-{severity} {bar.get(severity, '?       ')} | {label}: {message}")

def tcp_connect(ip, port, payload=None):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        s.connect((ip, port))
        if payload:
            s.send(payload)
        s.close()
        return True
    except:
        return False

def udp_send(ip, port, payload):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(2)
        s.sendto(payload, (ip, port))
        s.close()
        return True
    except:
        return False

print("=" * 65)
print("  Suricata Severity Trigger Test")
print(f"  Target: {TARGET_IP}")
print(f"  Started: {datetime.now()}")
print("=" * 65)

# ─────────────────────────────────────────────────────────────────────
# SEVERITY 1 — CRITICAL
# These payloads match ET EXPLOIT and ET MALWARE signatures
# ─────────────────────────────────────────────────────────────────────
print("\n── Severity 1 (Critical) ───────────────────────────────────────")

# Shellcode-like pattern in TCP stream — matches ET EXPLOIT rules
payload_shellcode = b"\x90" * 20 + b"\xeb\x0e\x5e\x56"  # NOP sled + jump pattern
result = tcp_connect(TARGET_IP, 4444, payload_shellcode)
log(1, "Shellcode pattern", f"sent to port 4444 ({'sent' if result else 'no listener, packet still seen'})")
time.sleep(DELAY)

# Metasploit meterpreter user agent — matches ET MALWARE
http_meterpreter = (
    b"GET /meterpreter HTTP/1.1\r\n"
    b"Host: " + TARGET_IP.encode() + b"\r\n"
    b"User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; Meterpreter)\r\n"
    b"Connection: close\r\n\r\n"
)
result = tcp_connect(TARGET_IP, 80, http_meterpreter)
log(1, "Meterpreter UA", f"HTTP request sent ({'connected' if result else 'no listener'})")
time.sleep(DELAY)

# EternalBlue SMB probe — matches ET EXPLOIT MS17-010 rules
smb_probe = (
    b"\x00\x00\x00\x54"          # NetBIOS session
    b"\xffSMB"                   # SMB header magic
    b"\x72"                      # SMBNegProt
    b"\x00" * 12
    b"\x53\x43"                  # dialect
)
result = tcp_connect(TARGET_IP, 445, smb_probe)
log(1, "SMB/EternalBlue probe", f"sent to port 445 ({'connected' if result else 'no listener'})")
time.sleep(DELAY)

# ─────────────────────────────────────────────────────────────────────
# SEVERITY 2 — HIGH
# Brute force and scan patterns
# ─────────────────────────────────────────────────────────────────────
print("\n── Severity 2 (High) ───────────────────────────────────────────")

# Rapid port scan burst — triggers ET SCAN Potential SSH Scan
log(2, "SSH scan burst", "scanning ports 20-25...")
for port in [20, 21, 22, 23, 24, 25]:
    tcp_connect(TARGET_IP, port)
    time.sleep(0.05)
log(2, "SSH scan burst", "done")
time.sleep(DELAY)

# Telnet brute force pattern — matches ET SCAN
log(2, "Telnet probe", "attempting connection...")
telnet_payload = b"root\r\nadmin\r\npassword\r\n"
tcp_connect(TARGET_IP, 23, telnet_payload)
log(2, "Telnet probe", "sent credentials to port 23")
time.sleep(DELAY)

# FTP brute force — matches ET SCAN FTP Brute Force rules
log(2, "FTP brute", "sending bad credentials...")
ftp_payload = b"USER root\r\nPASS toor\r\nUSER admin\r\nPASS admin\r\n"
tcp_connect(TARGET_IP, 21, ftp_payload)
log(2, "FTP brute", "sent to port 21")
time.sleep(DELAY)

# SQL injection pattern in HTTP — matches ET WEB_SERVER
http_sqli = (
    b"GET /?id=1'%20OR%20'1'='1%20UNION%20SELECT%20NULL,NULL,NULL-- HTTP/1.1\r\n"
    b"Host: " + TARGET_IP.encode() + b"\r\n"
    b"User-Agent: Mozilla/5.0\r\n"
    b"Connection: close\r\n\r\n"
)
tcp_connect(TARGET_IP, 80, http_sqli)
log(2, "SQL injection", "UNION SELECT payload sent to port 80")
time.sleep(DELAY)

# ─────────────────────────────────────────────────────────────────────
# SEVERITY 3 — MEDIUM
# Recon and policy violations
# ─────────────────────────────────────────────────────────────────────
print("\n── Severity 3 (Medium) ─────────────────────────────────────────")

# Nmap scripting engine user agent — matches ET SCAN Nmap
http_nmap = (
    b"GET / HTTP/1.1\r\n"
    b"Host: " + TARGET_IP.encode() + b"\r\n"
    b"User-Agent: Mozilla/5.0 (compatible; Nmap Scripting Engine)\r\n"
    b"Connection: close\r\n\r\n"
)
tcp_connect(TARGET_IP, 80, http_nmap)
log(3, "Nmap UA", "Nmap scripting engine user-agent sent")
time.sleep(DELAY)

# Nikto scanner UA — matches ET SCAN Nikto
http_nikto = (
    b"GET /admin HTTP/1.1\r\n"
    b"Host: " + TARGET_IP.encode() + b"\r\n"
    b"User-Agent: Nikto/2.1.6\r\n"
    b"Connection: close\r\n\r\n"
)
tcp_connect(TARGET_IP, 80, http_nikto)
log(3, "Nikto UA", "Nikto scanner user-agent sent")
time.sleep(DELAY)

# Path traversal — matches ET WEB_SERVER
http_traversal = (
    b"GET /../../../../etc/passwd HTTP/1.1\r\n"
    b"Host: " + TARGET_IP.encode() + b"\r\n"
    b"User-Agent: Mozilla/5.0\r\n"
    b"Connection: close\r\n\r\n"
)
tcp_connect(TARGET_IP, 80, http_traversal)
log(3, "Path traversal", "/etc/passwd traversal attempt sent")
time.sleep(DELAY)

# DNS version query — matches ET INFO DNS Version Request
dns_version = b"\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07version\x04bind\x00\x00\x10\x00\x03"
udp_send(TARGET_IP, 53, dns_version)
log(3, "DNS version", "DNS VERSION.BIND query sent to port 53")
time.sleep(DELAY)

# ─────────────────────────────────────────────────────────────────────
# SEVERITY 4 — LOW / INFORMATIONAL
# Policy and informational triggers
# ─────────────────────────────────────────────────────────────────────
print("\n── Severity 4 (Low/Info) ───────────────────────────────────────")

# curl user agent — matches ET INFO curl User-Agent
http_curl = (
    b"GET / HTTP/1.1\r\n"
    b"Host: " + TARGET_IP.encode() + b"\r\n"
    b"User-Agent: curl/7.88.1\r\n"
    b"Connection: close\r\n\r\n"
)
tcp_connect(TARGET_IP, 80, http_curl)
log(4, "curl UA", "curl user-agent request sent")
time.sleep(DELAY)

# Python requests UA — matches ET INFO Python-urllib
http_python = (
    b"GET / HTTP/1.1\r\n"
    b"Host: " + TARGET_IP.encode() + b"\r\n"
    b"User-Agent: python-requests/2.28.0\r\n"
    b"Connection: close\r\n\r\n"
)
tcp_connect(TARGET_IP, 80, http_python)
log(4, "Python UA", "python-requests user-agent sent")
time.sleep(DELAY)

print(f"\n[{datetime.now()}] All severity triggers sent.")
print("Check fast.log now:")
print("  sudo tail -30 /var/log/suricata/fast.log")
