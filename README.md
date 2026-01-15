Nmap Network Scanner (Python)

A clean Python wrapper around Nmap that lets you scan hosts, ranges, and subnets for open ports and services—right from the command line. Supports custom ports, extra Nmap flags, and optional OS detection with pretty output.


⚠️ Legal Notice: Only scan systems and networks you own or have explicit permission to test.


✨ Features


🧭 Flexible targets: single IP, hostname, comma-separated list, or CIDR (e.g., 192.168.1.0/24)

🚪 Port selection: single ports, lists, or ranges (e.g., 22,80,443 or 1-65535)

⚙️ Custom Nmap args: pass your favorite flags (default: -sS -Pn -T4)

🧠 Optional OS detection: use -o to add -O (often requires sudo/root)

🧾 Readable results: host state, MAC (when available), protocol, ports, service, product/version info, top OS guesses


📁 Repository Structure
```
.
├── scan.py            # Main script (Nmap wrapper)
├── README.md          # This file
└── requirements.txt   # (Optional) python-nmap dependency
```

requirements.txt
```
Plain Textpython-nmap>=0.7.1
```

🛠️ Installation

1) Install Nmap (system binary)

Ubuntu/Debian
```
sudo apt-get update && sudo apt-get install -y nmap
```

Fedora/CentOS/RHEL
```
sudo dnf install -y nmap    # or: sudo yum install -y nmap 
```

macOS (Homebrew)
```
brew install nmap
```

Windows

Download from https://nmap.org/download.html and ensure nmap.exe is on your PATH.



2) Install Python dependencies
```
pip install -r requirements.txt
#or
pip install python-nmap
```

▶️ Usage

The script exposes a CLI. Run -h to see all options:
```
python scan.py -hShow more lines
```

Scan a single host (default ports 1–1024)
```
python scan.py -t 192.168.1.10
```

Scan multiple hosts
```
python scan.py -t 192.168.1.10,192.168.1.20
```

Scan a CIDR subnet
```
python scan.py -t 192.168.1.0/24
```
Custom ports & faster timing
```
python scan.py -t 192.168.1.10 -p 22,80,443 -a "-sS -T4 -Pn"
```

Full range + OS detection (often requires sudo/root)
```
sudo python scan.py -t 192.168.1.10 -p 1-65535 -o
```

🧩 Command-line Options



🧩 Command-line Options

Option        Long           Description                                      Default
--------------------------------------------------------------------------------------------
-t           --target       Target(s): IP, hostname, CIDR, or list           Required
-p           --ports        Port list/range (e.g., 22,80,443 or 1-65535)     1-1024
-a           --arguments    Extra Nmap arguments                             -sS -Pn -T4
-o           --os-detect    Enable OS detection (adds -O)                    off


📤 Example Output
```
[+] Running: nmap -sS -Pn -T4 -p 22,80,443 192.168.1.10

================= Scan Results =================

Host: 192.168.1.10 (router.local)
State: up
MAC: AA:BB:CC:DD:EE:FF

Protocol: tcp
PORT    STATE   SERVICE VERSION
22      open    ssh     OpenSSH 8.4p1
80      open    http    nginx 1.18.0
443     open    https   nginx 1.18.0

OS Guesses:
 - Linux 5.X (accuracy: 96%)
 - DD-WRT (accuracy: 85%)

================================================
```

Notes:

MAC address may only appear on local/L2-accessible networks.
OS guesses require -o (which adds -O) and often elevated privileges.



🔍 How It Works (High Level)

Uses the python-nmap wrapper to call the local Nmap binary.

Parses results by host → protocol → port, and prints service/product/version when available.

OS detection is optional (enables Nmap’s -O flag).


🚑 Troubleshooting


ModuleNotFoundError: No module named 'nmap'

Install with pip install python-nmap.


nmap program was not found in path

Ensure Nmap is installed and available in your system PATH.


No results / empty output

Try -Pn to skip host discovery, or adjust firewall/permissions.


OS detection shows nothing

Use -o (adds -O) and run with sudo/admin when required.



🧭 Roadmap

 JSON/CSV output (for pipeline/SIEM ingestion)

 Parallelized scans for large subnets
 
 Optional service/version scan toggle (-sV)
 
 Combine with ARP discovery (Scapy) → feed live hosts to Nmap


🤝 Contributing

Fork the repo

Create a feature branch: git checkout -b feat/my-improvement

Commit changes: git commit -m "Add my improvement"

Push: git push origin feat/my-improvement

Open a Pull Request


📄 License

Specify your license of choice (e.g., MIT). Example:

MIT License — see LICENSE for details.


🙌 Credits

Built with python-nmap

Powered by the Nmap Security Scanner


If you want, I can also add:

A sample scan.py block in the README for quick copy/paste

A Makefile with shortcuts (make install, make scan TARGET=…)

A GitHub Actions workflow to lint/test basic CLI behavior
