import dpkt
import socket


def calculate_su_attempted(pcap_file):
    """
    Calculates the 'su_attempted' attribute from a PCAP file.

    Args:
        pcap_file (str): Path to the PCAP file.

    Returns:
        int: The count of 'su' command attempts.
    """
    su_attempted = 0

    for timestamp, buf in pcap_file:
        try:
            eth = dpkt.ethernet.Ethernet(buf)
            ip = eth.data
            protocol = ip.p

            # For TCP packets
            if protocol == dpkt.ip.IP_PROTO_TCP:
                tcp = ip.data

                if len(tcp.data) > 0:
                    payload = tcp.data.decode('utf-8', errors='ignore')

                    # Check for 'su' command in the payload
                    if 'su' in payload:
                        su_attempted += 1

            # For UDP packets
            elif protocol == dpkt.ip.IP_PROTO_UDP:
                udp = ip.data

                if len(udp.data) > 0:
                    payload = udp.data.decode('utf-8', errors='ignore')

                    # Check for 'su' command in the payload
                    if 'su' in payload:
                        su_attempted += 1

        except:
            # Skip any packets that can't be parsed
            continue

    return su_attempted
