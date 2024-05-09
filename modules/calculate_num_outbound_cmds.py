from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP, ICMP


def calculate_num_outbound_cmds(pcap_file):
    num_outbound_cmds = 0

    for pkt in pcap_file:
        # Check if the packet is TCP
        if pkt.haslayer(TCP):
            # Get the source and destination IP addresses
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst

            # Check if the packet is outbound
            if src_ip != dst_ip:
                # Check if the packet contains a command
                if pkt[TCP].dport in [21, 22, 23, 80, 179, 443, 8080]:
                    num_outbound_cmds += 1

        # Check if the packet is UDP
        elif pkt.haslayer(UDP):
            # Get the source and destination IP addresses
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst

            # Check if the packet is outbound
            if src_ip != dst_ip:
                # Check if the packet contains a command
                if pkt[UDP].dport in [53, 67, 68]:
                    num_outbound_cmds += 1

        # Check if the packet is ICMP
        elif pkt.haslayer(ICMP):
            # Get the source and destination IP addresses
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst

            # Check if the packet is outbound
            if src_ip != dst_ip:
                num_outbound_cmds += 1

    return num_outbound_cmds
