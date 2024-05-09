import dpkt
import collections


def calculate_srv_serror_rate(pcap_file):

    # Initialize a dictionary to keep track of the number of connections and errors for each service
    srv_stats = collections.defaultdict(lambda: [0, 0])  # [connections, errors]

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

                srv_stats[service][0] += 1

                if tcp.flags & (dpkt.tcp.TH_RST | dpkt.tcp.TH_FIN):
                    srv_stats[service][1] += 1

            # For UDP packets
            elif protocol == dpkt.ip.IP_PROTO_UDP:
                udp = ip.data
                src_port = udp.sport
                dst_port = udp.dport
                service = (src_port, dst_port)

                srv_stats[service][0] += 1

                # For UDP, there's no concept of RST or FIN flags. We consider all packets as successful.
                # Hence, we don't increment the error count.

            # For ICMP packets
            elif protocol == dpkt.ip.IP_PROTO_ICMP:
                # For ICMP, there's no concept of ports. Use 'ICMP' as service identifier.
                icmp_service = ('ICMP', 'ICMP')

                srv_stats[icmp_service][0] += 1

                # For ICMP, there's no concept of RST or FIN flags. We consider all packets as successful.
                # Hence, we don't increment the error count.

        except:
            # Skip any packets that can't be parsed
            continue

    # Calculate the srv_serror_rate
    total_conns = sum(stats[0] for stats in srv_stats.values())
    total_errors = sum(stats[1] for stats in srv_stats.values())
    srv_serror_rate = total_errors / total_conns if total_conns > 0 else 0

    return srv_serror_rate
