from scapy.all import *
from scapy.layers.inet import TCP, IP, UDP, ICMP


def calculate_num_shells(pcap_file):
    num_shells = 0

    for pkt in pcap_file:
        # Check if the packet is TCP and contains a shell command
        if pkt.haslayer(TCP) and pkt[TCP].dport in [22, 23]:
            num_shells += 1

        # Check if the packet is UDP and contains a shell command
        elif pkt.haslayer(UDP) and pkt[UDP].dport in [22, 23]:
            num_shells += 1

        # Check if the packet is ICMP and contains a shell command
        elif pkt.haslayer(ICMP):
            try:
                # Decode ICMP payload to string
                payload = pkt[ICMP].load.decode('utf-8', errors='ignore')

                # Check for shell commands in the payload
                if 'shell' in payload.lower():
                    num_shells += 1
            except:
                # Skip any packets that can't be parsed
                continue

    return num_shells
