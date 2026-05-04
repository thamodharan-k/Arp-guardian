🛡️ ARP Guardian
Real-time ARP Spoofing Detection, Simulation & Analysis Tool
A full-stack network security tool with a sleek web dashboard — built with Python, Flask & Scapy.

Python Flask Scapy License Platform

📸 Screenshot
Dashboard showing live ARP spoof detections with CRITICAL alerts, packet stats, and real-time monitoring.

ARP Guardian Dashboard

🚀 Features
📊 Live Dashboard — Real-time packet stats, spoof count, flood count, known hosts
📦 Packet Log — Every ARP packet captured with color-coded status (NORMAL / GRATUITOUS / SPOOF / FLOOD)
🚨 Alert System — Instant CRITICAL/MEDIUM alerts with timestamps, source IP & MAC
🔍 Network Scanner — ARP-scan your subnet to build a trusted IP→MAC table
📡 Live Monitor — Sniff real ARP traffic on any network interface
⚡ Attack Simulator — Generate spoof, gratuitous ARP, or flood packets for testing
🖥️ Known Hosts Table — Track all trusted devices on your network
📋 Report Generator — Export a full HTML security report with one click
🧠 How It Works
ARP (Address Resolution Protocol) is how computers on a network find each other's MAC addresses. Attackers can send fake ARP messages to redirect traffic through their machine — this is called ARP Spoofing or ARP Poisoning.

ARP Guardian monitors every ARP packet and checks:

Detection	How it works
SPOOF DETECTED	An IP is claimed by a MAC that doesn't match the trusted table
ARP FLOOD	A device sends 5+ ARP packets per second
GRATUITOUS ARP	Unsolicited "I am here" broadcast — a common pre-attack probe
New Host	A new device joined the network
🗂️ Project Structure
arp-guardian/
├── arp_web.py          # Main Flask web app (UI + API + detection engine)
├── arp_guardian.py     # CLI version (terminal only)
├── README.md           # This file
└── screenshot.png      # Dashboard screenshot
⚙️ Installation
Requirements
Python 3.8+
Windows: Npcap installed (for live monitoring)
Linux/Mac: Run with sudo for live monitoring
Install dependencies
pip install flask scapy rich colorama
▶️ Running the Web UI
python arp_web.py
Then open your browser and go to:

http://localhost:5000
The browser will open automatically.

🖥️ Usage Guide
1. Demo Mode (no admin needed)
Go to Monitor → Run Demo Runs offline with synthetic attack packets. No network or root required.

2. Scan Your Network
Go to Monitor → Scan Network

Subnet: 192.168.1.0/24   ← change to match your network
Builds the trusted IP→MAC table so the detector knows what's "normal".

3. Live Monitor
Go to Monitor → Live Monitor

Interface: Wi-Fi          ← or Ethernet, eth0, wlan0
Duration:  60             ← seconds
⚠️ Requires admin/sudo + Npcap on Windows

4. Simulate an Attack (lab only)
Go to Simulate

Attack Type	What it does
spoof	Sends fake ARP replies claiming the gateway's IP
gratuitous	Broadcasts unsolicited ARP — cache poisoning probe
flood	Sends rapid ARP requests to overwhelm the network
5. Generate Report
Go to Report → Open Full Report in New Tab Then press Ctrl+S (Windows) or Cmd+S (Mac) to save as HTML.

🔍 Finding Your Network Interface
Windows:

ipconfig
Look for Ethernet or Wi-Fi

Linux:

ip link show
Look for eth0, wlan0, ens33, etc.

Mac:

ifconfig
Look for en0 (Wi-Fi) or en1

🛠️ CLI Version
A terminal-only version is also included:

# Demo (no root)
python arp_guardian.py --mode demo

# Scan network
sudo python3 arp_guardian.py --mode scan --subnet 192.168.1.0/24

# Live monitor
sudo python3 arp_guardian.py --mode monitor --iface wlan0 --duration 60

# Simulate attack
sudo python3 arp_guardian.py --mode simulate --iface eth0 --attack spoof --count 20 --target 192.168.1.100 --gateway 192.168.1.1
⚠️ Legal Disclaimer
This tool is intended for educational purposes and authorized security testing only.
Only use this tool on networks you own or have explicit written permission to test.
Unauthorized use on public, corporate, or third-party networks is illegal and unethical.
The author is not responsible for any misuse of this software.

🧰 Built With
Tool	Purpose
Python	Core language
Flask	Web server & API
Scapy	Packet crafting & sniffing
Rich	CLI terminal output
📄 License
This project is licensed under the MIT License — feel free to use, modify, and distribute.

🙌 Author
THAMODHARAN K
