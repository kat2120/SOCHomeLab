# HomeSOC 🛡️

A fully operational, self-hosted Security Operations Center built on a Fedora Linux
mini PC. HomeSOC detects network intrusions, monitors host activity across two machines,
aggregates all logs into a unified dashboard, and delivers real-time threat alerts to
your phone — built entirely with free, open-source tools used in enterprise SOCs.

![Status](https://img.shields.io/badge/status-active-brightgreen)
![Platform](https://img.shields.io/badge/platform-Fedora%2042-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Cost](https://img.shields.io/badge/cost-%240-success)

## 🏗️ System Architecture

The environment consists of a centralized management node and distributed endpoints, integrating host-based and network-based detection.

- **Central SOC Node (Intel NUC):** Fedora 42 server hosting the Wazuh Manager, Indexer, Dashboard, and Suricata IDS.
- **Monitored Endpoint (ThinkPad T14):** Fedora 42 workstation running the Wazuh Agent for real-time telemetry.
- **Alert Engine:** Custom Python engine tailing JSON logs, performing VirusTotal IP reputation lookups, and routing critical alerts to Telegram.

## ⚙️ Tech Stack
 
| Tool | Version | Purpose | Status |
|------|---------|---------|--------|
| **Fedora Linux** | 42 | Base OS — Intel NUC and ThinkPad T14 | ✅ Done |
| **Wazuh** | 4.9.2 | HIDS — host intrusion detection + SIEM | ✅ Done |
| **Suricata** | Latest | NIDS — network intrusion detection | ✅ Done |
| **OpenSearch** | 2.19.4 | Alert indexing and search (via Wazuh) | ✅ Done |
| **Filebeat** | 7.10.2 | Ships Wazuh alerts to OpenSearch | ✅ Done |
| **Loki** | Latest | Log aggregation and storage | ✅ Done |
| **Grafana** | Latest | Unified log visualization dashboard | ✅ Done |
| **Grafana Alloy** | Latest | Log shipper (replaces Promtail in Loki v3) | ✅ Done |
| **Python 3** | 3.10+ | Alert parsing and automation engine | ✅ Done |
| **Telegram Bot API** | — | Real-time push notifications | ✅ Done |
| **firewalld** | — | Host firewall on Fedora | ✅ Done |
 
**Total project cost: $0** — every tool is free and open source.

## 📖 Documentation
 
Full step-by-step field manuals are available in `/docs`:
 
| Guide | Author | Coverage |
|-------|--------|----------|
| [Infrastructure Guide](docs/infrastructure-guide.html) | Kathlyn | Fedora setup, Wazuh stack, SSL certs, Filebeat, health checks |
| [Detection Guide](docs/detection-guide.html) | Richard | Suricata, custom rules, Python engine, VirusTotal, Telegram |

---
Built by **Kathlyn** & **Richard**
