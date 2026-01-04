from scapy.all import *
import random
import datetime
import base64

# --- Configuration ---
STUDENT_NAME = "JohnDoe"        # REPLACE WITH YOUR NAME
STUDENT_ID = "123456"           # REPLACE WITH YOUR ID
PCAP_FILENAME = "student_traffic.pcap"

# Function to generate a random IP
def random_ip():
    return f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}"

# Common Payload Generator
def get_payload():
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    return f"{STUDENT_NAME}-{STUDENT_ID} {timestamp}"

packet_list = []

print(f"[*] Starting packet generation for {STUDENT_NAME}...")

# 1. Student's Packet (TCP)
# Dest: 192.168.1.1, Port: 54321
pkt1 = IP(src=random_ip(), dst="192.168.1.1") / \
       TCP(dport=54321) / \
       Raw(load=get_payload())
packet_list.append(pkt1)
print("[+] Created Student TCP packet")

# 2. Port Scan Packets (10 packets)
# Dest: 192.168.1.2
# Services: HTTP(80), HTTPS(443), SSH(22), TELNET(23), FTP(21), 
#           DNS(53), RTSP(554), SQL(3306), RDP(3389), MQTT(1883)
ports = {
    80: "HTTP", 443: "HTTPS", 22: "SSH", 23: "TELNET", 21: "FTP",
    53: "DNS", 554: "RTSP", 3306: "SQL", 3389: "RDP", 1883: "MQTT"
}

for port, service in ports.items():
    # Note: DNS uses UDP usually, but port scans often check TCP too. 
    # Instructions say "Configure accordingly". Let's stick to TCP for scan consistency 
    # unless it's strictly UDP like DNS, but we will use TCP for the 'scan' attempt.
    # If you want strict protocol accuracy:
    proto = UDP if service == "DNS" else TCP
    
    pkt = IP(src=random_ip(), dst="192.168.1.2") / \
          proto(dport=port) / \
          Raw(load=get_payload())
    packet_list.append(pkt)
print("[+] Created 10 Port Scan packets")

# 3. Base64 Malicious Packets (5 packets)
# Dest: 192.168.1.3, Port: 8080, Payload: Base64 ID
encoded_id = base64.b64encode(STUDENT_ID.encode()).decode() # e.g., "MTIzNDU2"
for _ in range(5):
    pkt = IP(src=random_ip(), dst="192.168.1.3") / \
          TCP(dport=8080) / \
          Raw(load=encoded_id)
    packet_list.append(pkt)
print("[+] Created 5 Base64 packets")

# 4. DNS Suspicious Domain Packet (UDP)
# Dest: DNS IP of VM (Assuming 127.0.0.53 or 8.8.8.8 if unknown, let's use a placeholder)
# Note: Use '127.0.0.1' or check your VM's /etc/resolv.conf. 
# Here we use a generic internal IP as per typical lab setups.
dns_dst_ip = "192.168.1.254" # Adjust if you know the specific VM DNS IP
domain_name = "malicious.example.com"
pkt_dns = IP(src=random_ip(), dst=dns_dst_ip) / \
          UDP(dport=53) / \
          DNS(rd=1, qd=DNSQR(qname=domain_name))
packet_list.append(pkt_dns)
print("[+] Created Suspicious DNS packet")

# 5. Ping Test Packet (ICMP)
# Dest: 192.168.1.4
pkt_ping = IP(src=random_ip(), dst="192.168.1.4") / \
           ICMP() / \
           Raw(load="PingTest-2024")
packet_list.append(pkt_ping)
print("[+] Created Ping packet")

# Save to PCAP
wrpcap(PCAP_FILENAME, packet_list)
print(f"[*] All packets saved to {PCAP_FILENAME}")
