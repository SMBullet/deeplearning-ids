import dpkt
import socket
import collections


def calculate_dst_host_rerror_rate(pcap_file):

    # Initialize a dictionary to keep track of the connections and rejected connections for each destination host
    dst_host_stats = collections.defaultdict(lambda: [0, 0])  # [connections, rejected_connections]

    # Open the pcap file and process each packet
    for timestamp, buf in pcap_file:
        try:
            eth = dpkt.ethernet.Ethernet(buf)
            ip = eth.data

            # Get the destination IP address
            dst_ip = socket.inet_ntoa(ip.dst)

            # Increment the connection count for the destination host
            dst_host_stats[dst_ip][0] += 1

            # Check if the packet is an IP packet
            if isinstance(ip, dpkt.ip.IP):
                transport = ip.data

                # Check if the packet has the RST flag set (rejected connection)
                if isinstance(transport, dpkt.tcp.TCP) and transport.flags & dpkt.tcp.TH_RST:
                    dst_host_stats[dst_ip][1] += 1
                elif isinstance(transport, dpkt.udp.UDP):  # for UDP
                    # UDP doesn't have a concept of RST flag, but we'll increment connection count
                    dst_host_stats[dst_ip][0] += 1
                elif isinstance(transport, dpkt.icmp.ICMP):  # for ICMP
                    # ICMP doesn't have a concept of RST flag, but we'll increment connection count
                    dst_host_stats[dst_ip][0] += 1

        except:
            # Skip any packets that can't be parsed
            continue

    # Calculate the dst_host_rerror_rate
    total_conns = sum(stats[0] for stats in dst_host_stats.values())
    total_rejected = sum(stats[1] for stats in dst_host_stats.values())
    dst_host_rerror_rate = total_rejected / total_conns if total_conns > 0 else 0

    return dst_host_rerror_rate

