import dpkt
import socket


def calculate_serror_rate(pcap_file):

    # Initialize the number of connection errors and the total number of connections
    conn_errors = 0
    total_conns = 0

    # Open the pcap file and process each packet
    for timestamp, buf in pcap_file:
        try:
            eth = dpkt.ethernet.Ethernet(buf)
            ip = eth.data
            protocol = ip.p

            # Check if the packet is TCP
            if protocol == dpkt.ip.IP_PROTO_TCP:
                tcp = ip.data
                # Check if the packet has the RST or FIN flag set (connection error)
                if tcp.flags & (dpkt.tcp.TH_RST | dpkt.tcp.TH_FIN):
                    conn_errors += 1

            # Check if the packet is UDP
            elif protocol == dpkt.ip.IP_PROTO_UDP:
                udp = ip.data
                # UDP doesn't have connection setup or teardown, so we don't consider it as an error
                pass

            # For ICMP, we skip as it doesn't have the concept of flags
            elif protocol == dpkt.ip.IP_PROTO_ICMP:
                pass

            # Increment the total number of connections
            total_conns += 1

        except:
            # Skip any packets that can't be parsed
            continue

    # Calculate the serror_rate
    serror_rate = conn_errors / total_conns if total_conns > 0 else 0

    return serror_rate
