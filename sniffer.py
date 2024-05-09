from scapy.all import *
import os

# List of valid protocol types
valid_protocol_types = ['tcp', 'udp', 'icmp']

# List of valid service names
valid_services = ['aol', 'auth', 'bgp', 'courier', 'csnet_ns', 'ctf', 'daytime', 'discard', 'domain', 'domain_u', 'echo',
                  'eco_i', 'ecr_i', 'efs', 'exec', 'finger', 'ftp', 'ftp_data', 'gopher', 'harvest', 'hostnames', 'http',
                  'http_2784', 'http_443', 'http_8001', 'imap4', 'IRC', 'iso_tsap', 'klogin', 'kshell', 'ldap', 'link',
                  'login', 'mtp', 'name', 'netbios_dgm', 'netbios_ns', 'netbios_ssn', 'netstat', 'nnsp', 'nntp', 'ntp_u',
                  'other', 'pm_dump', 'pop_2', 'pop_3', 'printer', 'private', 'red_i', 'remote_job', 'rje', 'shell',
                  'smtp', 'sql_net', 'ssh', 'sunrpc', 'supdup', 'systat', 'telnet', 'tftp_u', 'tim_i', 'time', 'urh_i',
                  'urp_i', 'uucp', 'uucp_path', 'vmnet', 'whois', 'X11', 'Z39_50']

valid_packets_captured = 0
max_valid_packets = 10
valid_packets = []

def sniff_packets(interface=None):
    global valid_packets_captured, valid_packets

    def handle_packet(packet):
        global valid_packets_captured, valid_packets

        # Check if the packet has a transport layer protocol
        if packet.haslayer('TCP'):
            protocol_type = 'tcp'
        elif packet.haslayer('UDP'):
            protocol_type = 'udp'
        elif packet.haslayer('ICMP'):
            protocol_type = 'icmp'
        else:
            return

        # Check if the protocol type is valid
        if protocol_type not in valid_protocol_types:
            return

        # Get the service name
        if packet.haslayer('TCP'):
            service = packet['TCP'].dport
        elif packet.haslayer('UDP'):
            service = packet['UDP'].dport
        else:
            service = 'unknown'

        # Convert the service port number to service name
        try:
            service = socket.getservbyport(service)
        except:
            pass

        # Check if the service is valid
        if service not in valid_services:
            return

        print(f"Protocol Type: {protocol_type}, Service: {service}")
        valid_packets.append(packet)  # Add the valid packet to the list
        valid_packets_captured += 1

        # Stop sniffing if we have captured the maximum number of valid packets
        if valid_packets_captured >= max_valid_packets:
            return True

    packets = sniff(iface=interface, prn=lambda x: handle_packet(x), stop_filter=lambda x: valid_packets_captured >= max_valid_packets)

    # Get the directory of the script
    script_dir = os.path.dirname(os.path.abspath(__file__))

    # Save the valid packets to a PCAP file
    pcap_file = os.path.join(script_dir, 'valid_packets.pcap')
    wrpcap(pcap_file, valid_packets)

# Start sniffing packets on all interfaces
sniff_packets()