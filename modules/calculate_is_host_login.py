from scapy.all import *
from scapy.layers.inet import TCP, UDP, IP, ICMP


def calculate_is_host_login(packet):

    # Initialize host login flag
    is_host_login = 0

    # Define admin network subnet (e.g., '192.168.0.0/24')
    admin_subnet = '192.168.0.0/24'

    # Check if TCP layer exists
    if packet.haslayer(TCP):
        if (packet[TCP].dport == 22 or packet[TCP].dport == 23) and (
                IP(packet).src.startswith(admin_subnet) or IP(packet).dst.startswith(admin_subnet)):
            is_host_login = 1

    # Check if UDP layer exists
    elif packet.haslayer(UDP):
        if (packet[UDP].dport == 22 or packet[UDP].dport == 23) and (
                IP(packet).src.startswith(admin_subnet) or IP(packet).dst.startswith(admin_subnet)):
            is_host_login = 1

    # Check if ICMP layer exists
    elif packet.haslayer(ICMP):
        # Host login based on ICMP is less straightforward; here we're assuming ICMP echo request/reply as an example
        if (ICMP(packet).type == 8 or ICMP(packet).type == 0) and (
                IP(packet).src.startswith(admin_subnet) or IP(packet).dst.startswith(admin_subnet)):
            is_host_login = 1

    return is_host_login
