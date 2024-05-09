import dpkt
import socket


def calculate_root_shell(pcap_file):

    root_shell = 0
    for timestamp, buf in pcap_file:
        try:
            eth = dpkt.ethernet.Ethernet(buf)
            ip = eth.data
            protocol = ip.p

            # Check if the packet is TCP
            if protocol == dpkt.ip.IP_PROTO_TCP:
                tcp = ip.data
                # Check if the packet has the payload
                if len(tcp.data) > 0:
                    payload = tcp.data.decode('utf-8', errors='ignore')
                    if 'root shell' in payload.lower():
                        root_shell += 1

            # Check if the packet is UDP
            elif protocol == dpkt.ip.IP_PROTO_UDP:
                udp = ip.data
                # Check if the packet has the payload
                if len(udp.data) > 0:
                    payload = udp.data.decode('utf-8', errors='ignore')
                    if 'root shell' in payload.lower():
                        root_shell += 1

            # Check if the packet is ICMP
            elif protocol == dpkt.ip.IP_PROTO_ICMP:
                # ICMP doesn't have payload like TCP or UDP, so we skip it
                pass

        except:
            # Skip any packets that can't be parsed
            continue

    return root_shell
