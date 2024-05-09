import dpkt
import socket
import collections


def calculate_dst_host_diff_srv_rate(pcap_file):

    # Initialize a dictionary to keep track of the services and their associated destination hosts
    dst_host_services = collections.defaultdict(set)

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

                # Check if the packet has a payload
                if len(transport.data) > 0:
                    # Get the source and destination ports (represents the service)
                    src_port = transport.sport
                    dst_port = transport.dport
                    service = (src_port, dst_port)

                    # Add the destination host and service to the dictionary
                    dst_host_services[dst_ip].add(service)

        except:
            # Skip any packets that can't be parsed
            continue

    # Calculate the dst_host_diff_srv_rate
    total_connections = sum(len(services) for services in dst_host_services.values())
    unique_service_counts = [len(set(services)) for services in dst_host_services.values()]
    total_unique_services = sum(unique_service_counts)
    dst_host_diff_srv_rate = (total_unique_services - len(
        dst_host_services)) / total_connections if total_connections > 0 else 0

    return dst_host_diff_srv_rate
