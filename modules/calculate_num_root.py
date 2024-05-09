import dpkt
import socket


def calculate_num_root(pcap_file):

    num_root = 0

    for timestamp, buf in pcap_file:
        try:
            eth = dpkt.ethernet.Ethernet(buf)
            ip = eth.data

            # Check if the packet is a TCP packet and has the payload
            if isinstance(ip.data, dpkt.tcp.TCP) and len(ip.data.data) > 0:
                payload = ip.data.data.decode('utf-8', errors='ignore')

                # Check for root access messages in the payload
                if 'root access' in payload.lower():
                    num_root += 1

            # Check if the packet is a UDP packet and has the payload
            elif isinstance(ip.data, dpkt.udp.UDP) and len(ip.data.data) > 0:
                payload = ip.data.data.decode('utf-8', errors='ignore')

                # Check for root access messages in the payload
                if 'root access' in payload.lower():
                    num_root += 1

            # Check if the packet is an ICMP packet and has the payload
            elif isinstance(ip.data, dpkt.icmp.ICMP) and len(ip.data.data) > 0:
                payload = ip.data.data.decode('utf-8', errors='ignore')

                # Check for root access messages in the payload
                if 'root access' in payload.lower():
                    num_root += 1

        except:
            # Skip any packets that can't be parsed
            continue

    return num_root
