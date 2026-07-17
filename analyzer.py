import os
import sys
import re
from collections import Counter, defaultdict
from prettytable import PrettyTable
# Importing required modules from scapy
from scapy.all import rdpcap, IP, TCP, UDP, ICMP, Raw, ARP, DNS, DNSQR

# ==========================================
# Terminal Color Codes & UI Symbols
# ==========================================
class UI:
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    MAGENTA = '\033[95m'
    BLUE = '\033[94m'
    RESET = '\033[0m'
    BOLD = '\033[1m'
    
    # UI Icons for a modern look
    INFO = f"{BLUE}[i]{RESET}"
    SUCCESS = f"{GREEN}[★]{RESET}"
    WARN = f"{YELLOW}[⚡]{RESET}"
    ALERT = f"{RED}[!!]{RESET}"
    BULLET = f"{CYAN} ➜ {RESET}"

loaded_packets = []
current_file = None

def print_banner():
    os.system('clear' if os.name == 'posix' else 'cls')
    banner = f"""{UI.CYAN}{UI.BOLD}
    ██╗   ██╗ █████╗ ███╗   ██╗ ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗ 
    ██║   ██║██╔══██╗████╗  ██║██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗
    ██║   ██║███████║██╔██╗ ██║██║  ███╗██║   ██║███████║██████╔╝██║  ██║
    ╚██╗ ██╔╝██╔══██║██║╚██╗██║██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║
     ╚████╔╝ ██║  ██║██║ ╚████║╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝
      ╚═══╝  ╚═╝  ╚═╝╚═╝  ╚═══╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ 
    
                       TACTICAL PCAP ANALYZER v3.0
    {UI.RESET}
    {UI.MAGENTA}======================================================================={UI.RESET}
    {UI.YELLOW}   Type 'help' to view the operational command menu.{UI.RESET}
    {UI.MAGENTA}======================================================================={UI.RESET}
    """
    print(banner)

# ==========================================
# Module: Beautiful Educational Notes (Theory)
# ==========================================
def print_theory(topic):
    """
    Displays educational notes inside a clean ASCII box layout.
    """
    print(f"\n{UI.BLUE}   ╔════════════════════════════════════════════════════════════════════╗{UI.RESET}")
    print(f"{UI.BLUE}   ║  {UI.BOLD}ACADEMY DATABANK: THEORY LESSON{UI.RESET}                                   {UI.BLUE}║{UI.RESET}")
    print(f"{UI.BLUE}   ╠════════════════════════════════════════════════════════════════════╣{UI.RESET}")
    
    if topic == "stats":
        print(f"{UI.BLUE}   ║ {UI.CYAN}* TCP/UDP/ICMP:{UI.RESET} Core transport and diagnostic protocols.           {UI.BLUE}║{UI.RESET}")
        print(f"{UI.BLUE}   ║ {UI.CYAN}* Top Talkers:{UI.RESET} Identifying IPs with high packet counts is crucial  {UI.BLUE}║{UI.RESET}")
        print(f"{UI.BLUE}   ║   for spotting network bottlenecks, spam, or DDoS originators.     {UI.BLUE}║{UI.RESET}")
    
    elif topic == "threats":
        print(f"{UI.BLUE}   ║ {UI.CYAN}* ARP Spoofing (MITM):{UI.RESET} Attackers forge MAC addresses to intercept  {UI.BLUE}║{UI.RESET}")
        print(f"{UI.BLUE}   ║   local network traffic before it reaches the router.              {UI.BLUE}║{UI.RESET}")
        print(f"{UI.BLUE}   ║ {UI.CYAN}* Payload Extraction:{UI.RESET} Reading unencrypted protocol layers (HTTP/FTP){UI.BLUE}║{UI.RESET}")
        print(f"{UI.BLUE}   ║   to extract raw usernames and passwords.                          {UI.BLUE}║{UI.RESET}")
        
    elif topic == "dns":
        print(f"{UI.BLUE}   ║ {UI.CYAN}* DNS Tracking:{UI.RESET} DNS Question Records (DNSQR) act as a footprint,   {UI.BLUE}║{UI.RESET}")
        print(f"{UI.BLUE}   ║   revealing exactly which domains and services a target accessed.  {UI.BLUE}║{UI.RESET}")
        
    elif topic == "stateful":
        print(f"{UI.BLUE}   ║ {UI.CYAN}* Stateful Tracking:{UI.RESET} Monitoring the full TCP 3-Way Handshake.      {UI.BLUE}║{UI.RESET}")
        print(f"{UI.BLUE}   ║ {UI.CYAN}* State Violations:{UI.RESET} Unexpected ACK or Data packets without a prior {UI.BLUE}║{UI.RESET}")
        print(f"{UI.BLUE}   ║   SYN flag indicate potential firewall evasion (e.g., ACK Scans).  {UI.BLUE}║{UI.RESET}")
        
    elif topic == "exfil":
        print(f"{UI.BLUE}   ║ {UI.CYAN}* Data Exfiltration:{UI.RESET} Bypassing firewalls by hiding stolen data    {UI.BLUE}║{UI.RESET}")
        print(f"{UI.BLUE}   ║   inside allowed protocols (Protocol Tunneling).                   {UI.BLUE}║{UI.RESET}")
        print(f"{UI.BLUE}   ║ {UI.CYAN}* Indicators:{UI.RESET} Abnormally large ICMP payloads or extremely long,    {UI.BLUE}║{UI.RESET}")
        print(f"{UI.BLUE}   ║   encoded DNS subdomains.                                          {UI.BLUE}║{UI.RESET}")
        
    print(f"{UI.BLUE}   ╚════════════════════════════════════════════════════════════════════╝{UI.RESET}\n")

# ==========================================
# Core Module 1: Loading the PCAP File
# ==========================================
def load_file(filename):
    global loaded_packets, current_file
    if not os.path.exists(filename):
        print(f"\n  {UI.ALERT} Error: File '{filename}' not found.")
        return

    print(f"\n  {UI.INFO} Accessing data packets from {UI.BOLD}{filename}{UI.RESET}...")
    try:
        loaded_packets = rdpcap(filename)
        current_file = filename
        print(f"  {UI.SUCCESS} System Ready: {UI.BOLD}{len(loaded_packets)}{UI.RESET} packets successfully loaded into memory.")
    except Exception as e:
        print(f"  {UI.ALERT} Failed to parse PCAP file: {e}")

# ==========================================
# Core Module 2: Packet Statistics 
# ==========================================
def show_stats():
    if not loaded_packets:
        print(f"\n  {UI.WARN} Action Denied: Load a PCAP file first.")
        return

    print_theory("stats")

    tcp, udp, icmp, other = 0, 0, 0, 0
    ip_counter = Counter()

    for pkt in loaded_packets:
        if IP in pkt:
            ip_counter[pkt[IP].src] += 1 
            if TCP in pkt: tcp += 1
            elif UDP in pkt: udp += 1
            elif ICMP in pkt: icmp += 1
            else: other += 1

    # Formatting Output using PrettyTable with clean styles
    stat_table = PrettyTable()
    stat_table.field_names = ["Protocol", "Packet Count"]
    stat_table.add_row(["TCP", tcp])
    stat_table.add_row(["UDP", udp])
    stat_table.add_row(["ICMP", icmp])
    stat_table.add_row(["Other", other])
    
    print(f"  {UI.INFO} {UI.BOLD}Network Composition:{UI.RESET}")
    print(stat_table)

    top_talkers_table = PrettyTable()
    top_talkers_table.field_names = ["Source IP Address", "Packets Sent"]
    for ip, count in ip_counter.most_common(3):
        top_talkers_table.add_row([ip, count])

    print(f"\n  {UI.INFO} {UI.BOLD}Primary Broadcasters (Top 3):{UI.RESET}")
    print(top_talkers_table)

# ==========================================
# Core Module 3: Advanced Threat Engine
# ==========================================
def analyze_threats():
    if not loaded_packets:
        print(f"\n  {UI.WARN} Action Denied: Load a PCAP file first.")
        return

    print_theory("threats")
    print(f"  {UI.INFO} Initializing Threat Signatures Engine...\n")
    
    threats_found = 0
    syn_counter = Counter()
    arp_map = defaultdict(set) 

    for pkt in loaded_packets:
        # Rule 1: ARP Spoofing (MITM) Detection
        if pkt.haslayer(ARP) and pkt[ARP].op == 2:
            arp_map[pkt[ARP].psrc].add(pkt[ARP].hwsrc)

        if IP in pkt and TCP in pkt:
            src_ip = pkt[IP].src
            
            # Rule 2: SYN Flood / Port Scan Tracking
            if pkt[TCP].flags == "S":
                syn_counter[src_ip] += 1

            # Rule 3: Payload Extraction (Regex for Credentials)
            if pkt.haslayer(Raw):
                try:
                    payload = pkt[Raw].load.decode('utf-8', errors='ignore').strip()
                    if "pass=" in payload.lower() or "password=" in payload.lower() or "pwd=" in payload.lower():
                        print(f"  {UI.ALERT} {UI.MAGENTA}CRITICAL LEAK: Unencrypted credentials exposed by {src_ip}{UI.RESET}")
                        match = re.search(r'([a-zA-Z0-9_]*pass[a-zA-Z0-9_]*=[^&\s]+)', payload, re.IGNORECASE)
                        if match:
                            print(f"  {UI.BULLET} {UI.RED}Extracted Artifact: {match.group(1)}{UI.RESET}")
                        else:
                            print(f"  {UI.BULLET} {UI.RED}Raw Snippet: {payload[:60]}...{UI.RESET}")
                        threats_found += 1
                except:
                    pass

    # Evaluate ARP Spoofing
    for ip, mac_set in arp_map.items():
        if len(mac_set) > 1:
            print(f"  {UI.ALERT} {UI.RED}ARP SPOOFING DETECTED: IP {ip} claimed by multiple MACs!{UI.RESET}")
            print(f"  {UI.BULLET} {UI.YELLOW}Associated MACs: {', '.join(mac_set)}{UI.RESET}")
            threats_found += 1

    # Evaluate Port Scans
    for ip, count in syn_counter.items():
        if count > 50:
            print(f"  {UI.WARN} {UI.YELLOW}RECONNAISSANCE: Possible Port Scan from {ip} ({count} SYN packets){UI.RESET}")
            threats_found += 1

    if threats_found == 0:
        print(f"  {UI.SUCCESS} Perimeter Secure. No advanced threats detected.")
    else:
        print(f"\n  {UI.ALERT} {UI.RED}Scan Complete. Total anomalies detected: {threats_found}{UI.RESET}")

# ==========================================
# Core Module 4: DNS Traffic Analysis
# ==========================================
def analyze_dns():
    if not loaded_packets:
        print(f"\n  {UI.WARN} Action Denied: Load a PCAP file first.")
        return

    print_theory("dns")
    print(f"  {UI.INFO} Extracting DNS Question Records (DNSQR)...\n")
    
    dns_queries = Counter()
    
    for pkt in loaded_packets:
        if pkt.haslayer(DNSQR):
            try:
                domain = pkt[DNSQR].qname.decode('utf-8').rstrip('.')
                dns_queries[domain] += 1
            except:
                pass

    if not dns_queries:
        print(f"  {UI.WARN} No DNS resolution traffic found in this capture.")
        return

    dns_table = PrettyTable()
    dns_table.field_names = ["Queried Domain", "Request Count"]
    for domain, count in dns_queries.most_common(10):
        dns_table.add_row([domain, count])
        
    print(f"  {UI.INFO} {UI.BOLD}Target Destinations (Top 10):{UI.RESET}")
    print(dns_table)

# ==========================================
# Core Module 5: Stateful Inspection Engine
# ==========================================
def analyze_stateful():
    if not loaded_packets:
        print(f"\n  {UI.WARN} Action Denied: Load a PCAP file first.")
        return

    print_theory("stateful")
    print(f"  {UI.INFO} Validating TCP 3-Way Handshake Sequencing...\n")
    
    connection_states = {}
    violations = 0
    
    for pkt in loaded_packets:
        if IP in pkt and TCP in pkt:
            src = pkt[IP].src
            dst = pkt[IP].dst
            flags = pkt[TCP].flags
            
            # Connection ID (Order-independent mapping)
            conn_id = tuple(sorted([src, dst]))
            
            if flags == "S": 
                connection_states[conn_id] = "SYN_SEEN"
            elif flags == "SA":
                if connection_states.get(conn_id) == "SYN_SEEN":
                    connection_states[conn_id] = "ESTABLISHED"
            elif "A" in flags or "P" in flags:
                if conn_id not in connection_states:
                    print(f"  {UI.ALERT} {UI.RED}STATE VIOLATION: Unsolicited ACK/Data packet detected.{UI.RESET}")
                    print(f"  {UI.BULLET} {UI.YELLOW}Vector: {src} -> {dst} (Possible Evasion/Scan){UI.RESET}")
                    violations += 1
                    connection_states[conn_id] = "VIOLATION_LOGGED"

    if violations == 0:
        print(f"  {UI.SUCCESS} TCP sequences validated. No state violations found.")
    else:
        print(f"\n  {UI.ALERT} {UI.RED}Total Stateful Violations Found: {violations}{UI.RESET}")
        print(f"  {UI.INFO} {UI.YELLOW}Note: False positives may occur if capture started mid-session.{UI.RESET}")

# ==========================================
# Core Module 6: Data Exfiltration Detection
# ==========================================
def analyze_exfiltration():
    if not loaded_packets:
        print(f"\n  {UI.WARN} Action Denied: Load a PCAP file first.")
        return

    print_theory("exfil")
    print(f"  {UI.INFO} Scanning for Protocol Tunneling Signatures...\n")

    exfil_found = 0

    for pkt in loaded_packets:
        # Rule 1: ICMP Tunneling Anomaly (Size)
        if ICMP in pkt and pkt.haslayer(Raw):
            payload_len = len(pkt[Raw].load)
            if payload_len > 100: 
                src_ip = pkt[IP].src
                dst_ip = pkt[IP].dst
                print(f"  {UI.ALERT} {UI.MAGENTA}ICMP TUNNEL: Massive Ping payload detected!{UI.RESET}")
                print(f"  {UI.BULLET} {UI.YELLOW}Vector: {src_ip} -> {dst_ip} | Size: {payload_len} bytes{UI.RESET}")
                exfil_found += 1

        # Rule 2: DNS Tunneling Anomaly (Length)
        if pkt.haslayer(DNSQR):
            try:
                qname = pkt[DNSQR].qname.decode('utf-8').rstrip('.')
                if len(qname) > 60: 
                    print(f"  {UI.ALERT} {UI.RED}DNS TUNNEL: Suspiciously long, encoded DNS query!{UI.RESET}")
                    print(f"  {UI.BULLET} {UI.YELLOW}Query String: {qname}{UI.RESET}")
                    exfil_found += 1
            except:
                pass

    if exfil_found == 0:
        print(f"  {UI.SUCCESS} No exfiltration channels detected in this capture.")
    else:
        print(f"\n  {UI.ALERT} {UI.RED}Total Exfiltration Anomalies Found: {exfil_found}{UI.RESET}")

# ==========================================
# Interactive CLI Loop
# ==========================================
def start_cli():
    print_banner()
    while True:
        try:
            file_prompt = f"({current_file}) " if current_file else ""
            # Updated Command Prompt Look
            user_input = input(f"\n{UI.BOLD}Vanguard {UI.CYAN}{file_prompt}{UI.RESET}> ").strip().split()
            
            if not user_input:
                continue
            
            command = user_input[0].lower()
            
            if command == "help":
                print(f"\n  {UI.BOLD}Operational Commands:{UI.RESET}")
                print(f"    {UI.YELLOW}load <file.pcap>{UI.RESET}  - Load network capture into memory")
                print(f"    {UI.YELLOW}stats{UI.RESET}             - General packet mapping and top talkers")
                print(f"    {UI.YELLOW}dns{UI.RESET}               - Trace DNS resolution footprint")
                print(f"    {UI.YELLOW}threats{UI.RESET}           - Run MITM and cleartext credential scans")
                print(f"    {UI.YELLOW}stateful{UI.RESET}          - TCP 3-Way Handshake validation (Firewall logic)")
                print(f"    {UI.YELLOW}exfil{UI.RESET}             - Hunt for covert ICMP/DNS protocol tunneling")
                print(f"    {UI.YELLOW}exit{UI.RESET}              - Terminate application")
                
            elif command == "load":
                if len(user_input) < 2:
                    print(f"  {UI.WARN} Usage: load <filename.pcap>")
                else:
                    load_file(user_input[1])
                    
            elif command == "stats": show_stats()
            elif command == "dns": analyze_dns()
            elif command == "threats": analyze_threats()
            elif command == "stateful": analyze_stateful()
            elif command == "exfil": analyze_exfiltration()
            elif command in ["exit", "quit"]:
                print(f"\n  {UI.INFO} Terminating Vanguard session. Goodbye.\n")
                sys.exit(0)
            else:
                print(f"  {UI.WARN} Unknown directive. Type 'help' for the menu.")
                
        except KeyboardInterrupt:
            print(f"\n\n  {UI.ALERT} System override detected. Terminating Vanguard.\n")
            sys.exit(0)

if __name__ == "__main__":
    start_cli()