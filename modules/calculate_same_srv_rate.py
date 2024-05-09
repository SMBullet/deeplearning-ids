import dpkt
import collections


def calculate_same_srv_rate(pcap_file):

    # Initialize a dictionary to keep track of the number of connections for each service
    srv_conn_counts = collections.defaultdict(int)

    # Open the pcap file and process each packet
    for timestamp, buf in pcap_file:
        try:
            eth = dpkt.ethernet.Ethernet(buf)
            ip = eth.data
            protocol = ip.p

            # Check if the packet is TCP
            if protocol == dpkt.ip.IP_PROTO_TCP:
                tcp = ip.data
                src_port = tcp.sport
                dst_port = tcp.dport
                service = (src_port, dst_port)
                srv_conn_counts[service] += 1

            # Check if the packet is UDP
            elif protocol == dpkt.ip.IP_PROTO_UDP:
                udp = ip.data
                src_port = udp.sport
                dst_port = udp.dport
                service = (src_port, dst_port)
                srv_conn_counts[service] += 1

            # For ICMP, we skip as it doesn't have the concept of ports
            elif protocol == dpkt.ip.IP_PROTO_ICMP:
                pass

        except:
            # Skip any packets that can't be parsed
            continue

    # Calculate the same_srv_rate
    total_conns = sum(srv_conn_counts.values())
    squared_counts = [count ** 2 for count in srv_conn_counts.values()]
    sum_squared_counts = sum(squared_counts)
    same_srv_rate = sum_squared_counts / (total_conns ** 2) if total_conns > 0 else 0

    return same_srv_rate
