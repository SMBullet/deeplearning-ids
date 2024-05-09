import dpkt
import collections


def calculate_srv_diff_host_rate(pcap_file):

    # Initialize a dictionary to keep track of the services and their associated hosts
    srv_hosts = collections.defaultdict(set)

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

                src_ip = ip.src
                dst_ip = ip.dst

                srv_hosts[service].add(src_ip)
                srv_hosts[service].add(dst_ip)

            # For UDP packets
            elif protocol == dpkt.ip.IP_PROTO_UDP:
                udp = ip.data
                src_port = udp.sport
                dst_port = udp.dport
                service = (src_port, dst_port)

                src_ip = ip.src
                dst_ip = ip.dst

                srv_hosts[service].add(src_ip)
                srv_hosts[service].add(dst_ip)

            # For ICMP packets
            elif protocol == dpkt.ip.IP_PROTO_ICMP:
                src_ip = ip.src
                dst_ip = ip.dst

                # For ICMP, there's no concept of ports. Use IP addresses to determine hosts.
                icmp_service = ('ICMP', 'ICMP')
                srv_hosts[icmp_service].add(src_ip)
                srv_hosts[icmp_service].add(dst_ip)

        except:
            # Skip any packets that can't be parsed
            continue

    # Calculate the srv_diff_host_rate
    total_conns = sum(len(hosts) for hosts in srv_hosts.values())
    unique_host_counts = [len(set(hosts)) for hosts in srv_hosts.values()]
    sum_unique_host_counts = sum(unique_host_counts)
    srv_diff_host_rate = sum_unique_host_counts / total_conns if total_conns > 0 else 0

    return srv_diff_host_rate
