from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP, ICMP


def calculate_land(packet):
    """
    Calculate the 'land' feature for a given packet.

    Args:
        packet (scapy.packet.Packet): The packet to analyze.

    Returns:
        int: 1 if the source and destination IP addresses and port numbers are the same, 0 otherwise.
    """
    if packet.haslayer(IP):
        ip_layer = packet.getlayer(IP)

        # Check if the packet has TCP, UDP, or ICMP layer
        if packet.haslayer(TCP):
            transport_layer = packet.getlayer(TCP)
        elif packet.haslayer(UDP):
            transport_layer = packet.getlayer(UDP)
        elif packet.haslayer(ICMP):
            transport_layer = packet.getlayer(ICMP)
        else:
            return 0

        # Check if the source and destination IP addresses and port numbers are the same
        if ip_layer.src == ip_layer.dst and transport_layer.sport == transport_layer.dport:
            return 1

    return 0
