import dpkt
import socket
import collections

def calculate_dst_host_same_src_port_rate(pcap_file):

    # Initialize a dictionary to keep track of the source ports and their associated destination hosts
    dst_host_src_ports = collections.defaultdict(lambda: collections.defaultdict(int))

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

                # Get the source port
                src_port = 0  # Default value for ICMP and UDP
                if isinstance(transport, dpkt.tcp.TCP):
                    src_port = transport.sport
                elif isinstance(transport, dpkt.udp.UDP):
                    src_port = transport.sport
                elif isinstance(transport, dpkt.icmp.ICMP):
                    # ICMP doesn't have a concept of source port, use a default value
                    src_port = 0

                # Increment the count for the source port and destination host
                dst_host_src_ports[dst_ip][src_port] += 1

        except:
            # Skip any packets that can't be parsed
            continue

    # Calculate the dst_host_same_src_port_rate
    total_connections = sum(sum(port_counts.values()) for port_counts in dst_host_src_ports.values())
    same_src_port_connections = sum(
        count ** 2 for port_counts in dst_host_src_ports.values() for count in port_counts.values())
    dst_host_same_src_port_rate = same_src_port_connections / (total_connections ** 2) if total_connections > 0 else 0

    return dst_host_same_src_port_rate
