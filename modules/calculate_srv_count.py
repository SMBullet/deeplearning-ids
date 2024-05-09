import dpkt
import collections


def calculate_srv_count(pcap_file):

    # Initialize a set to keep track of the unique services
    services = set()

    # Open the pcap file and process each packet
    for timestamp, buf in pcap_file:
        try:
            eth = dpkt.ethernet.Ethernet(buf)
            ip = eth.data
            protocol = ip.p

            # For TCP packets
            if protocol == dpkt.ip.IP_PROTO_TCP:
                tcp = ip.data
                src_port = tcp.sport
                dst_port = tcp.dport
                service = (src_port, dst_port)
                services.add(service)

            # For UDP packets
            elif protocol == dpkt.ip.IP_PROTO_UDP:
                udp = ip.data
                src_port = udp.sport
                dst_port = udp.dport
                service = (src_port, dst_port)
                services.add(service)

            # For ICMP packets
            elif protocol == dpkt.ip.IP_PROTO_ICMP:
                # ICMP doesn't have ports, so we can't determine service. Skipping it.
                pass

        except:
            # Skip any packets that can't be parsed
            continue

    # Calculate the srv_count
    srv_count = len(services)

    return srv_count
