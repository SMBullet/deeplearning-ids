import sys

import dpkt
import collections

def calculate_diff_srv_rate(pcap_file):
    # Initialize a set to keep track of the unique services
    unique_services = set()

    # Initialize a counter to count the occurrences of each service
    service_counter = collections.Counter()

    # Open the pcap file and process each packet
    for timestamp, buf in pcap_file:
        try:
            eth = dpkt.ethernet.Ethernet(buf)
            ip = eth.data
            tcp = ip.data

            # Get the source and destination ports (represents the service)
            src_port = tcp.sport
            dst_port = tcp.dport
            service = (src_port, dst_port)

            # Add the service to the set of unique services
            unique_services.add(service)

            # Count the occurrence of the service
            service_counter[service] += 1
        except:
            # Skip any packets that can't be parsed
            continue

    # Calculate the diff_srv_rate
    total_services = len(unique_services)
    total_conns = sum(service_counter.values())

    if total_conns == 0:
        # If there are no connections, return 0
        diff_srv_rate = 0
    else:
        diff_srv_rate = (total_services - 1) / total_conns

    return diff_srv_rate
