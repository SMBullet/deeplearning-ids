import dpkt
import socket
import collections

def calculate_dst_host_srv_diff_host_rate(pcap_file):

    # Initialize a dictionary to keep track of the services and their associated destination hosts
    srv_dst_hosts = collections.defaultdict(lambda: collections.defaultdict(set))

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

                    # Add the destination host to the set of hosts for the service
                    srv_dst_hosts[service][dst_ip].add(timestamp)
        except:
            # Skip any packets that can't be parsed
            continue

    # Calculate the dst_host_srv_diff_host_rate
    total_connections = sum(len(hosts) for hosts_per_srv in srv_dst_hosts.values() for hosts in hosts_per_srv.values())
    unique_host_counts = [len(set(hosts)) for hosts_per_srv in srv_dst_hosts.values() for hosts in hosts_per_srv.values()]
    sum_unique_host_counts = sum(unique_host_counts)
    dst_host_srv_diff_host_rate = sum_unique_host_counts / total_connections if total_connections > 0 else 0

    return dst_host_srv_diff_host_rate
