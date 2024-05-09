import dpkt


def calculate_count(pcap_file):
    count = 0

    for timestamp, buf in pcap_file:
        try:
            eth = dpkt.ethernet.Ethernet(buf)
            ip = eth.data

            # Check if the packet is IP
            if isinstance(ip, dpkt.ip.IP):
                count += 1

        except:
            # Skip any packets that can't be parsed
            continue

    return count
