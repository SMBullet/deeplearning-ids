from scapy.all import *
from scapy.layers.inet import TCP, UDP


def calculate_service(packet):
    """
    Calculate the service for a given packet based on the port numbers.
    
    Args:
        packet (scapy.packet.Packet): The packet to analyze.
        
    Returns:
        str: The service name if recognized, or 'other' if not recognized.
    """
    # Define a dictionary mapping port numbers to service names
    service_map = {
        7: 'echo',
        9: 'discard',
        11: 'systat',
        13: 'daytime',
        17: 'qotd',
        19: 'chargen',
        20: 'ftp-data',
        21: 'ftp',
        22: 'ssh',
        23: 'telnet',
        25: 'smtp',
        37: 'time',
        42: 'name',
        43: 'nicname',
        53: 'domain',
        67: 'dhcps',
        68: 'dhcpc',
        69: 'tftp',
        70: 'gopher',
        79: 'finger',
        80: 'http',
        88: 'kerberos',
        101: 'hostname',
        107: 'rtelnet',
        109: 'pop2',
        110: 'pop3',
        111: 'sunrpc',
        113: 'auth',
        119: 'nntp',
        123: 'ntp',
        135: 'epmap',
        139: 'netbios-ssn',
        143: 'imap',
        179: 'bgp',
        389: 'ldap',
        443: 'https',
        445: 'microsoft-ds',
        465: 'smtp+ssl',
        513: 'login',
        514: 'shell',
        515: 'printer',
        543: 'klogin',
        544: 'kshell',
        1723: 'pptp',
        3306: 'mysql',
        5900: 'vnc',
        6000: 'X11',
        6667: 'irc'
    }

    if packet.haslayer(TCP) or packet.haslayer(UDP):
        dport = packet[TCP].dport if packet.haslayer(TCP) else packet[UDP].dport
        service = service_map.get(dport, 'other')
        return service
    else:
        return 'other'