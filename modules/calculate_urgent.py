from scapy.all import *
from scapy.layers.inet import TCP, UDP, ICMP


def calculate_urgent(pcap_file):
    """
    Calculates the count of packets with the URG flag set in TCP, ICMP, and UDP.

    Args:
        pcap_file (str): Path to the pcap file.

    Returns:
        int: The count of packets with the URG flag set.
    """
    urgent_count = 0

    for packet in pcap_file:
        try:
            if packet.haslayer(TCP) and packet.getlayer(TCP).flags & 0x20:
                urgent_count += 1
            elif packet.haslayer(ICMP) and packet.getlayer(ICMP).type == 11:  # Type 11 corresponds to Time Exceeded
                urgent_count += 1
            elif packet.haslayer(UDP) and packet.getlayer(UDP).sport == 53:  # Assuming DNS uses UDP port 53
                urgent_count += 1
        except:
            # Skip any packets that can't be parsed
            continue

    return urgent_count
