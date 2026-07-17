# Vanguard-Tactical-PCAP-Analyzer

# Vanguard: Tactical PCAP Analyzer v3.0

Vanguard is an advanced, terminal-based network packet analysis and threat-hunting tool written in Python. Designed for cybersecurity students, SOC analysts, and network defenders, Vanguard bridges the gap between raw packet capture and educational theory. It transforms offline `.pcap` and `.pcapng` files into structured, readable telemetry, exposing network anomalies, credential leaks, and covert hacking techniques while teaching the fundamental theory behind them.

---

## 🚀 Key Features

Vanguard is built with modular engines, each targeting a specific layer of network analysis and forensics:

### 1. Educational Theory Engine (`stats` & `threats`)
* **Learn While You Analyze:** Before presenting analytical results, Vanguard displays an "Academy Databank" theory lesson explaining core protocols and how attackers manipulate them.

### 2. Network Composition & Telemetry (`stats`)
* Implements **Data Visualization** via structured ASCII tables to map the overall network breakdown (TCP, UDP, ICMP).
* Automatically identifies the network's **Top 3 Talkers** (highest-volume source IP addresses) to spot potential data exfiltration or active bots.

### 3. Footprint & Destinational Tracking (`dns`)
* Parses **DNS Question Records (DNSQR)** from raw UDP streams.
* Generates a structural table mapping the **Top 10 Tracked Domains** visited by users on the network, vital for threat intelligence and user tracking.

### 4. Advanced Threat & Signature Detection (`threats`)
* **ARP Spoofing (MITM) Detection:** Monitors network layer responses to track if multiple MAC addresses claim a single IP, identifying Man-in-the-Middle attacks.
* **Reconnaissance Tracking:** Detects Nmap scans (XMAS, SYN Floods, Port Scans) by tracking unusual TCP flag anomalies (`FIN`, `PSH`, `URG`, `SYN`) against custom thresholds.
* **Deep Packet Inspection (DPI):** Implements Regular Expressions (Regex) to securely scan raw unencrypted protocol layers (like HTTP/FTP), automatically extracting exposed credential strings (usernames and passwords) from transit.

### 5. Stateful Inspection Engine (`stateful`)
* Emulates **Next-Generation Firewall (NGFW)** connection tracking logic.
* Validates full TCP 3-Way Handshake sequences (`SYN` ➜ `SYN-ACK` ➜ `ACK`) and logs **State Violations** when unsolicited ACK or data packets arrive without established history.

### 6. Covert Channel & Protocol Tunneling Detection (`exfil`)
* Scans for data exfiltration techniques used by advanced attackers to sneak data past corporate firewalls:
  * **ICMP Tunneling:** Flags abnormally large ping payloads (>100 bytes) carrying hidden data.
  * **DNS Tunneling:** Identifies abnormally long, base64/hex-encoded domain strings (>60 characters) used to leak data via port 53.

---

## 📦 7.Prerequisites & Installation

### Check Dependencies
Ensure you have Python installed, then verify if `scapy` is available:
```bash
---


# 8Installation
python -c "import scapy; print('Scapy is installed!')"

pip install scapy prettytable

python analyzer.py



## Operational Command Menu:
help - View the command execution menu.

load <file.pcapng> - Load a Wireshark capture file into structural memory.

stats - Generate general packet distribution mapping and top talkers.

dns - Trace and extract the DNS footprint/visited domains.

threats - Scan for active MITM attacks, port reconnaissance, and credential leaks.

stateful - Run stateful connection validation to identify out-of-sequence packets.

exfil - Hunt for covert ICMP/DNS data tunneling operations.

exit - Terminate the session safely.

