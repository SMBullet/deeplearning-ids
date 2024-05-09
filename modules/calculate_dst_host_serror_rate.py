import dpkt
import socket
import collections

def calculate_dst_host_serror_rate(pcap_file):

    # Initialize a dictionary to keep track of the connections and errors for each destination host
    dst_host_stats = collections.defaultdict(lambda: [0, 0])  # [connections, errors]

    # Open the pcap file and process each packet
    for timestamp, buf in pcap_file:
        try:
            eth = dpkt.ethernet.Ethernet(buf)
            ip = eth.data

            # Get the destination IP address
            dst_ip = socket.inet_ntoa(ip.dst)

            # Check if the packet is an IP packet
            if isinstance(ip, dpkt.ip.IP):
                transport = ip.data

                # Increment the connection count for the destination host
                dst_host_stats[dst_ip][0] += 1

                # Check if the packet has the RST or FIN flag set (connection error)
                if isinstance(transport, dpkt.tcp.TCP) and transport.flags & (dpkt.tcp.TH_RST | dpkt.tcp.TH_FIN):
                    dst_host_stats[dst_ip][1] += 1
                elif isinstance(transport, dpkt.icmp.ICMP):
                    # For ICMP, consider the whole packet as an error (as it doesn't have flags like TCP)
                    dst_host_stats[dst_ip][1] += 1
        except:
            # Skip any packets that can't be parsed
            continue

    # Calculate the dst_host_serror_rate
    total_conns = sum(stats[0] for stats in dst_host_stats.values())
    total_errors = sum(stats[1] for stats in dst_host_stats.values())
    dst_host_serror_rate = total_errors / total_conns if total_conns > 0 else 0

    return dst_host_serror_rate
