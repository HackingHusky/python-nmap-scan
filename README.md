# Network Asset Discovery and Reconnaissance Utility
<img width="1376" height="768" alt="image" src="https://github.com/user-attachments/assets/be592b5b-9441-4f54-ab81-30925a278ad9" />


An asynchronous, command-line Python abstraction layer built on top of the Nmap Security Scanner. This utility programmatically orchestrates targeted port scans, subnet discovery, service fingerprinting, and operating system detection to provide structured infrastructure auditing reports.

---

## Core Features

*   **Dynamic Target Input:** Seamlessly handles discrete IP addresses, fully qualified hostnames, comma-separated target arrays, or standard CIDR notation blocks (e.g., `192.168.1.0/24`).
*   **Granular Port Definition:** Supports targeted port arrays, localized lists, or exhaustive port boundary ranges (e.g., `1-65535`).
*   **Argument Passthrough:** Supports raw Nmap argument insertion to configure scanning speeds, evasion protocols, and timing templates.
*   **Heuristic OS Fingerprinting:** Integrates optional passive and active stack analysis to determine remote operating system builds.
*   **Normalized Console Output:** Aggregates and clean-prints active host states, physical MAC layers, layer-4 protocols, open services, and specific software versions.

---

## Technical Architecture

The utility relies on an external operational binary along with a standardized Python wrapper interface:

*   **Core Binary:** Nmap (Network Mapper)
*   **Python Wrapper Library:** `python-nmap`

---

## Deployment & Installation

### 1. Host Binary Installation

Ensure the foundational Nmap binary is provisioned within your system environment variables (`PATH`).

#### Debian / Ubuntu Environments
```bash
sudo apt-get update && sudo apt-get install -y nmap
```

#### RHEL / CentOS / Fedora Environments
```bash
sudo dnf install -y nmap
```

#### macOS Environments (via Homebrew)
```bash
brew install nmap
```

#### Windows Environments
Download the official binary setup package from the [Nmap Release Portal](https://nmap.org/download.html) and append the target binary directory to your system environment variables.

### 2. Python Environment & Library Provisioning

To avoid global package space pollution, deployment within a virtual environment (`venv`) is highly recommended.

#### Virtual Environment Initialization (Linux/macOS)
```bash
sudo apt update && sudo apt install -y python3-venv
python3 -m venv nmap-env
source nmap-env/bin/activate
```

#### Dependency Installation
With your isolated execution context active, download the protocol translation library:
```bash
pip install python-nmap>=0.7.1
```

---

## Operational Guide

The CLI framework features structured flags to control your testing boundaries. Review help documentation using the standard flag:

```bash
python scan.py -h
```

### Command Arguments Layout

| Option | Long Flag | Field Description | Operational Default |
| :--- | :--- | :--- | :--- |
| `-t` | `--target` | Hostname, individual IP address, CIDR block, or comma-separated target list. | **[REQUIRED]** |
| `-p` | `--ports` | Specific target port selection, comma list, or numeric hyphenated range. | `1-1024` |
| `-a` | `--arguments` | Raw Nmap scanning flags forwarded directly to the subsystem interface. | `-sS -Pn -T4` |
| `-o` | `--os-detect` | Triggers active OS stack identification (appends `-O`). | `Disabled` |

### Command Execution Examples

#### Core Infrastructure Validation
```bash
python scan.py -t 192.168.1.10
```

#### Distributed Host Array Scan
```bash
python scan.py -t 192.168.1.10,192.168.1.20
```

#### Subnet Mask Enumeration
```bash
python scan.py -t 192.168.1.0/24
```

#### High-Speed Custom Port Profile
```bash
python scan.py -t 192.168.1.10 -p 22,80,443 -a "-sS -T4 -Pn"
```

#### Full Perimeter Audit with OS Fingerprinting
*Note: Active stack scanning typically requires root-level administrative access.*
```bash
sudo python scan.py -t 192.168.1.10 -p 1-65535 -o
```

---

## Standard Output Profiling

Upon completing asset interrogation, the output displays structured reporting blocks:

```text
[+] Running: nmap -sS -Pn -T4 -p 22,80,443 192.168.1.10

================= Scan Results =================
Host: 192.168.1.10 (router.local)
State: up
MAC: AA:BB:CC:DD:EE:FF
Protocol: tcp

PORT    STATE  SERVICE  VERSION
22/tcp  open   ssh      OpenSSH 8.4p1
80/tcp  open   http     nginx 1.18.0
443/tcp open   https    nginx 1.18.0

OS Guesses:
- Linux 5.X (accuracy: 96%)
- DD-WRT (accuracy: 85%)
================================================
```

---

## System Troubleshooting

*   **Error:** `ModuleNotFoundError: No module named 'nmap'`
    *   *Remediation:* Your execution context lacks the python wrapper. Run `pip install python-nmap` inside your active virtual environment.
*   **Error:** `nmap program was not found in path`
    *   *Remediation:* The underlying system binary is missing or unmapped. Verify that your system can successfully process the standalone command `nmap --version`.
*   **Issue:** Null/Empty Response Body
    *   *Remediation:* Network firewalls may be actively filtering out ICMP requests. Inject the `-Pn` flag within your custom arguments to treat targets as online and skip initial discovery.

---

## Compliance and Legal Warning

Targeting network assets with automated scanning infrastructure without explicit, formal authorization is illegal and unethical. This script is distributed solely as architectural testing scaffolding for enterprise vulnerability lifecycle management, automated internal audits, and legitimate educational exercises. 

Users assume all operational risk and legal liabilities for execution routines mapped against environments lacking signed, prior technical validation consent.

---

## License

This software utility is open-source software licensed under the terms of the **MIT License**. Refer to the repository `LICENSE` file for redistribution guidelines.
