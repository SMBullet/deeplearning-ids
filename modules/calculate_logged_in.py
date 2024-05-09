import dpkt
import socket


def calculate_logged_in(pcap_file):
    logged_in = 0

    for timestamp, buf in pcap_file:
        try:
            eth = dpkt.ethernet.Ethernet(buf)
            ip = eth.data

            # Check if the packet is an IP packet
            if isinstance(ip, dpkt.ip.IP):
                transport = ip.data

                # Check if the packet is a TCP packet and has the payload
                if isinstance(transport, dpkt.tcp.TCP) and len(transport.data) > 0:
                    payload = transport.data.decode('utf-8', errors='ignore')

                    # Check for successful login messages in the payload
                    if 'logged in' in payload.lower():
                        logged_in += 1

        except:
            # Skip any packets that can't be parsed
            continue

    return logged_in
