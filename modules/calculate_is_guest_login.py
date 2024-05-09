from scapy.all import *
from scapy.layers.inet import TCP, IP, UDP, ICMP

def calculate_is_guest_login(packet):
    # Initialize guest login flag
    is_guest_login = 0
    # Define guest network subnet (e.g., '192.168.1.0/24')
    guest_subnet = '192.168.1.0/24'

    # Check if the packet has an IP layer
    if packet.haslayer(IP):
        ip_packet = packet[IP]

        # Check if TCP layer exists
        if packet.haslayer(TCP):
            # Check protocol and ports (FTP, HTTP, HTTPS)
            if (packet[TCP].dport == 21 or packet[TCP].dport == 80 or packet[TCP].dport == 443) and \
                    (ip_packet.src.startswith(guest_subnet) or ip_packet.dst.startswith(guest_subnet)):
                is_guest_login = 1

        # Check if UDP layer exists
        elif packet.haslayer(UDP):
            # Check if source or destination IP is in the guest subnet
            if ip_packet.src.startswith(guest_subnet) or ip_packet.dst.startswith(guest_subnet):
                is_guest_login = 1

        # Check if ICMP layer exists
        elif packet.haslayer(ICMP):
            # Check if source or destination IP is in the guest subnet
            if ip_packet.src.startswith(guest_subnet) or ip_packet.dst.startswith(guest_subnet):
                is_guest_login = 1

    return is_guest_login