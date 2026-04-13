#!/usr/bin/env python3
"""
web_attacks.py
Simulates common web attacks over raw HTTP.
Triggers Suricata: ET WEB_SERVER, ET SQL, ET XSS rules.
"""

import socket
import time
from datetime import datetime

TARGET_IP   = "[Your Server IP Address]"   # any HTTP server on your network
TARGET_PORT = 9090
DELAY       = 0.5

# Payloads that match Suricata's ET ruleset signatures
ATTACKS = [
    # SQL injection attempts
    ("SQL Injection 1",    "GET /?id=1'%20OR%20'1'='1 HTTP/1.1"),
    ("SQL Injection 2",    "GET /?user=admin'--&pass=x HTTP/1.1"),
    ("SQL Injection 3",    "GET /?q=1%20UNION%20SELECT%201,2,3-- HTTP/1.1"),

    # XSS attempts
    ("XSS 1",             "GET /?q=<script>alert(1)</script> HTTP/1.1"),
    ("XSS 2",             "GET /?name=<img%20src=x%20onerror=alert(1)> HTTP/1.1"),

    # Path traversal
    ("Path Traversal 1",  "GET /../../../../etc/passwd HTTP/1.1"),
    ("Path Traversal 2",  "GET /..%2F..%2F..%2Fetc%2Fshadow HTTP/1.1"),

    # Common backdoor/shell probes
    ("Shell probe",       "GET /shell.php?cmd=id HTTP/1.1"),
    ("Webshell probe",    "GET /wp-content/uploads/shell.php HTTP/1.1"),
    ("Admin probe",       "GET /admin/config.php HTTP/1.1"),

    # Suspicious user agents
    ("Bad UA — sqlmap",   "GET / HTTP/1.1"),     # sent with sqlmap UA below
    ("Bad UA — nikto",    "GET / HTTP/1.1"),      # sent with nikto UA below
]

BAD_AGENTS = [
    "sqlmap/1.7 (https://sqlmap.org)",
    "Nikto/2.1.6",
    "masscan/1.3",
    "python-requests/2.28 (scanner)",
]

def send_http(ip, port, request_line, user_agent="Mozilla/5.0"):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        sock.connect((ip, port))
        http_request = (
            f"{request_line}\r\n"
            f"Host: {ip}\r\n"
            f"User-Agent: {user_agent}\r\n"
            f"Connection: close\r\n\r\n"
        )
        sock.send(http_request.encode())
        response = sock.recv(256).decode(errors="ignore")
        status = response.split("\r\n")[0] if response else "no response"
        sock.close()
        return status
    except Exception as e:
        return str(e)

print(f"[{datetime.now()}] Starting web attack simulation against {TARGET_IP}:{TARGET_PORT}\n")

for name, req in ATTACKS:
    agent = "Mozilla/5.0"
    status = send_http(TARGET_IP, TARGET_PORT, req, agent)
    print(f"  [{name:20s}] {status}")
    time.sleep(DELAY)

# Send requests with suspicious user agents
print("\n  --- Suspicious user agent probes ---")
for agent in BAD_AGENTS:
    status = send_http(TARGET_IP, TARGET_PORT, "GET / HTTP/1.1", agent)
    print(f"  [UA: {agent[:30]:30s}] {status}")
    time.sleep(DELAY)

print(f"\n[{datetime.now()}] Web attack simulation complete")
