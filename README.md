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

- **Central SOC Node (Intel NUC):** Fedora 42 server hosting the Wazuh Manager, Indexer, Dashboard, and Suricata IDS [cite: 1, 2].
- **Monitored Endpoint (ThinkPad T14):** Fedora 42 workstation running the Wazuh Agent for real-time telemetry [cite: 1, 2].
- **Alert Engine:** Custom Python engine tailing JSON logs, performing VirusTotal IP reputation lookups, and routing critical alerts to Telegram [cite: 1].

## 🛠️ The Tech Stack

| Component | Technology | Role |
| :--- | :--- | :--- |
| **HIDS / SIEM** | Wazuh 4.9 | Host intrusion detection, file integrity monitoring, and MITRE mapping [cite: 1, 2]. |
| **NIDS** | Suricata | Network-based detection using Emerging Threats community rules [cite: 1]. |
| **Search Engine** | OpenSearch | High-performance indexing and storage of all security events [cite: 1, 2]. |
| **Data Shipper** | Filebeat | Securely ships logs from the manager to the indexer via SSL [cite: 1, 2]. |
| **Automation** | Python | Custom alert enrichment and notification routing [cite: 1]. |
| **OS** | Fedora 42 | Hardened base operating system with SSH/Firewall hardening [cite: 1, 2]. |

## 🚀 Key Features

- **24/7 Threat Detection:** Continuous monitoring of logins, sudo commands, and file changes [cite: 1].
- **OT/ICS Focus:** Configured to handle industrial protocol anomalies and traffic patterns [cite: 1].
- **Instant Alerts:** Critical threats are delivered to mobile devices via Telegram within seconds [cite: 1].
- **Threat Intel Enrichment:** Automatic VirusTotal API integration for suspicious IP scoring [cite: 1].
- **Hardened Infrastructure:** Custom SSH ports (7389), key-based authentication, and automated security updates [cite: 1, 2].

## 📖 Project Documentation

Detailed step-by-step guides are available in the repository:

1.  [**Infrastructure Guide**](documentation-website/infrastructure-guide.html): Covers bare-metal Fedora setup, SSL certificate bootstrapping, and service hardening [cite: 2].
2.  [**Detection Guide**](https://github.com/kat2120/SOCHomeLab): Covers Suricata rule-writing, custom Python alert logic, and malware analysis workflows [cite: 1].

## 🛡️ Challenges Overcome

- **SSL Bootstrapping:** Manually diagnosed and repaired Wazuh certificate tool failures on non-clean installations [cite: 1, 2].
- **XML Validation:** Automated the repair of corrupted `ossec.conf` files using Python parsers [cite: 1, 2].
- **Field Mapping:** Resolved OpenSearch `illegal_argument_exception` errors by implementing custom index templates for correct data typing [cite: 1].

---
Built by **Kathlyn** & **Richard** | British Columbia Institute of Technology (BCIT) [cite: 1, 2]
