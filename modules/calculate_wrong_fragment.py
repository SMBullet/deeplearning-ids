from scapy.all import *


from scapy.layers.inet import IP


def calculate_wrong_fragment(packet):
    wrong_fragment_count = 0
    if packet.haslayer(IP) and packet.getlayer(IP).flags & 3 != 0:
        wrong_fragment_count += 1
    return wrong_fragment_count
