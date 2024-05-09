import dpkt
import socket
import collections

def calculate_dst_host_srv_rerror_rate(pcap_file):

    # Initialize a dictionary to keep track of the services, destination hosts, and their associated connection stats
    srv_dst_host_stats = collections.defaultdict(
        lambda: collections.defaultdict(lambda: [0, 0]))  # [connections, rejected_connections]

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

                # Get the source and destination ports (represents the service)
                if isinstance(transport, dpkt.tcp.TCP) or isinstance(transport, dpkt.udp.UDP) or isinstance(transport, dpkt.icmp.ICMP):
                    src_port = transport.sport
                    dst_port = transport.dport
                    service = (src_port, dst_port)

                    # Increment the connection count for the service and destination host
                    srv_dst_host_stats[service][dst_ip][0] += 1

                    # Check if the packet has the RST or ICMP type/code indicating an error
                    if (isinstance(transport, dpkt.tcp.TCP) and transport.flags & dpkt.tcp.TH_RST) \
                            or (isinstance(transport, dpkt.icmp.ICMP) and (transport.type == dpkt.icmp.ICMP_UNREACH or transport.type == dpkt.icmp.ICMP_TIMXCEED)):
                        srv_dst_host_stats[service][dst_ip][1] += 1
        except:
            # Skip any packets that can't be parsed
            continue

    # Calculate the dst_host_srv_rerror_rate
    total_conns = sum(dst_host_stats[0] for srv_stats in srv_dst_host_stats.values() for dst_host_stats in srv_stats.values())
    total_rejected = sum(dst_host_stats[1] for srv_stats in srv_dst_host_stats.values() for dst_host_stats in srv_stats.values())
    dst_host_srv_rerror_rate = total_rejected / total_conns if total_conns > 0 else 0

    return dst_host_srv_rerror_rate
