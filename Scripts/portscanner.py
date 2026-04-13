#!/usr/bin/env python3
"""
port_scanner.py
Simulates an Nmap-style port scan against a target.
Triggers Suricata rules: ET SCAN, GPL SCAN.
"""

import socket
import sys
import threading
from datetime import datetime

TARGET = "[Your Server IP Address]"        # change to a host on your network
START_PORT = 1
END_PORT = 9999
TIMEOUT = 0.5
THREADS = 50

print(f"[{datetime.now()}] Starting port scan on {TARGET}")
print(f"Scanning ports {START_PORT}-{END_PORT} with {THREADS} threads\n")

open_ports = []
lock = threading.Lock()

def scan_port(port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(TIMEOUT)
        result = sock.connect_ex((TARGET, port))
        if result == 0:
            with lock:
                open_ports.append(port)
                print(f"  [OPEN] Port {port}")
        sock.close()
    except Exception:
        pass

threads = []
for port in range(START_PORT, END_PORT + 1):
    t = threading.Thread(target=scan_port, args=(port,))
    threads.append(t)
    t.start()
    # Throttle — keep active threads under limit
    while threading.active_count() > THREADS:
        pass

for t in threads:
    t.join()

print(f"\n[{datetime.now()}] Scan complete. Open ports: {open_ports}")
