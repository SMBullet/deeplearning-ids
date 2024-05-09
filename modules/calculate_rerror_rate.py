import dpkt
import socket


def calculate_rerror_rate(pcap_file):
    """
    Calculates the rerror_rate attribute from a pcap file.

    Args:
        pcap_file (str): Path to the pcap file.

    Returns:
        float: The rerror_rate value.
    """
    # Initialize the number of rejected connections and the total number of connections
    rejected_conns = 0
    total_conns = 0

    for timestamp, buf in pcap_file:
        try:
            eth = dpkt.ethernet.Ethernet(buf)
            ip = eth.data
            protocol = ip.p

            # Check if the packet is TCP
            if protocol == dpkt.ip.IP_PROTO_TCP:
                tcp = ip.data
                # Check if the packet has the RST flag set (rejected connection)
                if tcp.flags & dpkt.tcp.TH_RST:
                    rejected_conns += 1

            # Check if the packet is UDP
            elif protocol == dpkt.ip.IP_PROTO_UDP:
                udp = ip.data
                # For UDP, we consider the absence of a reply as an error
                if udp.dport not in [53, 67, 68] and udp.sport not in [53, 67, 68]:
                    rejected_conns += 1

            # Check if the packet is ICMP
            elif protocol == dpkt.ip.IP_PROTO_ICMP:
                # ICMP doesn't have flags like TCP, so we'll consider it as an error
                rejected_conns += 1

            # Increment the total number of connections
            total_conns += 1
        except:
            # Skip any packets that can't be parsed
            continue

    # Calculate the rerror_rate
    rerror_rate = rejected_conns / total_conns if total_conns > 0 else 0

    return rerror_rate
