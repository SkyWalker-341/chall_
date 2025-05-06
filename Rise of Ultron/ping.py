from scapy.all import IP, ICMP, Raw, wrpcap, Ether

# Destination IP (can be a dummy IP for crafting)
target_ip = "192.168.1.10"

# The data string to send one character per ICMP packet
data = "[AABBSSDDGGTTHHUU1llii[AABBSSD9DGGTTHHUUllii[AABBSSDDGGTTH2HUUllii[AABBSSDDGGTTHHUUllii.[AABBSSDDGGTTHHUU1llii[AABBSS6DDGGTTHHUUllii[AABBSSDDGGTTHHUU8llii[AABBSSDDGGTTHHUUllii.[AABBSSDDGGTTHHUUl2lii[AABBSSDDGGT3THHUUllii[AABBSSDDGGTTHHUUl7lii[AABBSSDDGGTTHHUUllii.[AABBSSDDGGTTHHUU4llii[AABBSSDDGGTTHHUU7llii]]]]]]]]]]]]]]"

packets = []

# Build ICMP Echo Request packets, each carrying one character
for char in data:
    ether = Ether()
    ip = IP(dst=target_ip)
    icmp = ICMP(type=8)  # Echo request
    raw = Raw(load=char)
    packet = ether / ip / icmp / raw
    packets.append(packet)

# Save to PCAP file
wrpcap("ultron_icmp_flag.pcap", packets)
print("PCAP file 'ultron_icmp_flag.pcap' generated successfully.")
