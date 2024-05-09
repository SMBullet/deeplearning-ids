from scapy.all import *

def calculate_src_bytes(packet):
    """
    Calculate the number of bytes sent from the source for a given packet.
    
    Args:
        packet (scapy.packet.Packet): The packet to analyze.
        
    Returns:
        int: The number of bytes sent from the source, or 0 if the packet doesn't have a payload.
    """
    if packet.haslayer(Raw):
        return len(packet.getlayer(Raw).load)
    else:
        return 0
