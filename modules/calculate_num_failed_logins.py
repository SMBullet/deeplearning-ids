import dpkt
import socket


def calculate_num_failed_logins(pcap_file):
    num_failed_logins = 0

    for timestamp, buf in pcap_file:
        try:
            eth = dpkt.ethernet.Ethernet(buf)
            ip = eth.data

            # Check if the packet is an IP packet
            if isinstance(ip, dpkt.ip.IP):
                transport = ip.data

                # Check if the packet has a payload
                if len(transport.data) > 0:
                    payload = transport.data.decode('utf-8', errors='ignore')

                    # Check for failed login messages in the payload
                    if 'failed login' in payload.lower():
                        num_failed_logins += 1

        except:
            # Skip any packets that can't be parsed
            continue

    return num_failed_logins
