import dpkt


def calculate_hot(pcap_file):
    """
    Calculates the 'hot' attribute from a PCAP file.

    Args:
        pcap_file: dpkt.pcap.Reader object

    Returns:
        int: The count of packets where the 'hot' attribute is 1.
    """
    hot_count = 0

    for timestamp, buf in pcap_file:
        try:
            eth = dpkt.ethernet.Ethernet(buf)
            ip = eth.data

            # Check if the packet is an IP packet
            if isinstance(ip, dpkt.ip.IP):
                transport = ip.data

                # Check if the packet has the 'hot' attribute
                if hasattr(transport, 'hot') and transport.hot == 1:
                    hot_count += 1

        except:
            # Skip any packets that can't be parsed
            continue

    return hot_count
