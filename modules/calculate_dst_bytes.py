from scapy.all import *


def calculate_dst_bytes(packet):
    if packet.haslayer(Raw):
        return len(packet.getlayer(Raw).load)
    else:
        return 0