import dpkt
import socket

def calculate_num_file_creations(pcap_file):

    num_file_creations = 0

    for timestamp, buf in pcap_file:
        try:
            eth = dpkt.ethernet.Ethernet(buf)
            ip = eth.data

            # Check if the packet is an IP packet
            if eth.type == dpkt.ethernet.ETH_TYPE_IP:
                protocol = ip.p

                # Check for TCP protocol
                if protocol == dpkt.ip.IP_PROTO_TCP:
                    tcp = ip.data

                    # Check if the TCP packet has the payload
                    if len(tcp.data) > 0:
                        payload = tcp.data.decode('utf-8', errors='ignore')

                        # Check for file creation messages in the payload
                        if 'file created' in payload.lower():
                            num_file_creations += 1

                # Check for UDP protocol
                elif protocol == dpkt.ip.IP_PROTO_UDP:
                    udp = ip.data

                    # Check if the UDP packet has the payload
                    if len(udp.data) > 0:
                        payload = udp.data.decode('utf-8', errors='ignore')

                        # Check for file creation messages in the payload
                        if 'file created' in payload.lower():
                            num_file_creations += 1

                # Check for ICMP protocol
                elif protocol == dpkt.ip.IP_PROTO_ICMP:
                    icmp = ip.data

                    # Check if the ICMP packet has the payload
                    if len(icmp.data) > 0:
                        payload = icmp.data.decode('utf-8', errors='ignore')

                        # Check for file creation messages in the payload
                        if 'file created' in payload.lower():
                            num_file_creations += 1

        except:
            # Skip any packets that can't be parsed
            continue

    return num_file_creations
