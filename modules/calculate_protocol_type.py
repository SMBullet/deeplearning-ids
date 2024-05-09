from scapy.all import *
from scapy.layers.inet import TCP, UDP, ICMP


def calculate_protocol_type(packet):
    """
    Calculate the protocol type for a given packet.
    
    Args:
        packet (scapy.packet.Packet): The packet to analyze.
        
    Returns:
        str: The protocol type ('tcp', 'udp', 'icmp', or 'other').
    """
    if packet.haslayer(TCP):
        return 'tcp'
    elif packet.haslayer(UDP):
        return 'udp'
    elif packet.haslayer(ICMP):
        return 'icmp'
    else:
        return 'other'