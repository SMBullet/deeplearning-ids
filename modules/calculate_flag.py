from scapy.all import *
from scapy.layers.inet import TCP


def calculate_flag(packet):
    """
    Calculate the flag for a given packet based on the TCP flags.
    
    Args:
        packet (scapy.packet.Packet): The packet to analyze.
        
    Returns:
        str: The flag name if recognized, or 'OTH' (other) if not recognized.
    """
    if packet.haslayer(TCP):
        tcp_flags = packet.getlayer(TCP).flags
        
        # Define a dictionary mapping flag values to flag names
        flag_map = {
            0x01: 'FIN',
            0x02: 'SYN',
            0x04: 'RST',
            0x08: 'PSH',
            0x10: 'ACK',
            0x20: 'URG',
            0x40: 'ECE',
            0x80: 'CWR',
        }
        
        flag_names = []
        for flag_value, flag_name in flag_map.items():
            if tcp_flags & flag_value:
                flag_names.append(flag_name)
        
        if len(flag_names) == 0:
            return 'OTH'  # Other
        elif len(flag_names) == 1:
            if flag_names[0] == 'SYN':
                return 'S0'
            elif flag_names[0] == 'FIN':
                return 'SF'
            elif flag_names[0] == 'RST':
                return 'RSTR'
            else:
                return 'OTH'  # Other
        elif len(flag_names) == 2:
            if set(flag_names) == set(['SYN', 'ACK']):
                return 'S1'
            elif set(flag_names) == set(['RST', 'ACK']):
                return 'RSTO'
            elif set(flag_names) == set(['SYN', 'ACK', 'RST']):
                return 'RSTOS0'
            else:
                return 'OTH'  # Other
        elif len(flag_names) == 3 and set(flag_names) == set(['SYN', 'ACK', 'RST']):
            return 'S2'
        elif len(flag_names) == 4 and set(flag_names) == set(['SYN', 'ACK', 'RST', 'FIN']):
            return 'S3'
        else:
            return 'OTH'  # Other
    else:
        return 'OTH'  # Other
