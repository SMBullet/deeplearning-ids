import pandas as pd
import csv
from pymongo import MongoClient

# Read the CSV file
df = pd.read_csv("data.csv", skiprows=1, header=None)

# Define a function to create new columns based on the protocol
def protocol_to_columns(protocol):
    if protocol == "tcp":
        return [1, 0, 0]
    elif protocol == "udp":
        return [0, 1, 0]
    elif protocol == "icmp":
        return [0, 0, 1]
    else:
        return [0, 0, 0]

# Define a function to create new columns based on the service
def service_to_columns(service):
    services = ['aol', 'auth', 'bgp', 'courier', 'csnet_ns', 'ctf', 'daytime', 'discard', 'domain', 'domain_u', 'echo', 'eco_i', 'ecr_i', 'efs', 'exec', 'finger', 'ftp', 'ftp_data', 'gopher', 'harvest', 'hostnames', 'http', 'http_2784', 'http_443', 'http_8001', 'imap4', 'IRC', 'iso_tsap', 'klogin', 'kshell', 'ldap', 'link', 'login', 'mtp', 'name', 'netbios_dgm', 'netbios_ns', 'netbios_ssn', 'netstat', 'nnsp', 'nntp', 'ntp_u', 'other', 'pm_dump', 'pop_2', 'pop_3', 'printer', 'private', 'red_i', 'remote_job', 'rje', 'shell', 'smtp', 'sql_net', 'ssh', 'sunrpc', 'supdup', 'systat', 'telnet', 'tftp_u', 'tim_i', 'time', 'urh_i', 'urp_i', 'uucp', 'uucp_path', 'vmnet', 'whois', 'X11', 'Z39_50']
    if service in services:
        return [1 if s == service else 0 for s in services]
    else:
        return [0] * len(services)

# Define a function to create new columns based on the flag
def flag_to_columns(flag):
    flags = {'OTH', 'REJ', 'RSTO', 'RSTOS0', 'RSTR', 'S0', 'S1', 'S2', 'S3', 'SF', 'SH'}
    if flag in flags:
        return [1 if f == flag else 0 for f in flags]
    else:
        return [0] * len(flags)


# Assuming the first column is the protocol column
protocol_column_index = 1

# Apply the function to create new columns for the protocol
new_protocol_columns = df.iloc[:, protocol_column_index].apply(protocol_to_columns).apply(pd.Series)

# Insert the new protocol columns at the same position as the original column
df = pd.concat([df.iloc[:, :protocol_column_index], new_protocol_columns, df.iloc[:, protocol_column_index+1:]], axis=1)

# Assuming the second column is the service column
service_column_index = 4

# Apply the function to create new columns for the service
new_service_columns = df.iloc[:, service_column_index].apply(service_to_columns).apply(pd.Series)

# Insert the new service columns at the same position as the original column
df = pd.concat([df.iloc[:, :service_column_index], new_service_columns, df.iloc[:, service_column_index+1:]], axis=1)

flag_column_index = 74

# Apply the function to create new columns for the flag
new_flag_columns = df.iloc[:, flag_column_index].apply(flag_to_columns).apply(pd.Series)

# Insert the new flag columns at the same position as the original column
df = pd.concat([df.iloc[:, :flag_column_index], new_flag_columns, df.iloc[:, flag_column_index+1:]], axis=1)

# Save the modified DataFrame to a new CSV file
df.to_csv("bin.csv", index=False, header=False)

# Read the CSV file
df2= pd.read_csv("bin.csv", header=None)

# Set column names
column_names = [
    'duration', 'tcp', 'udp', 'icmp', 'aol', 'auth', 'bgp', 'courier', 'csnet_ns', 'ctf', 'daytime', 'discard', 'domain', 'domain_u', 'echo', 'eco_i', 'ecr_i', 'efs', 'exec', 'finger', 'ftp', 'ftp_data', 'gopher', 'harvest', 'hostnames', 'http', 'http_2784', 'http_443', 'http_8001', 'imap4', 'IRC', 'iso_tsap', 'klogin', 'kshell', 'ldap', 'link', 'login', 'mtp', 'name', 'netbios_dgm', 'netbios_ns', 'netbios_ssn', 'netstat', 'nnsp', 'nntp', 'ntp_u', 'other', 'pm_dump', 'pop_2', 'pop_3', 'printer', 'private', 'red_i', 'remote_job', 'rje', 'shell', 'smtp', 'sql_net', 'ssh', 'sunrpc', 'supdup', 'systat', 'telnet', 'tftp_u', 'tim_i', 'time', 'urh_i', 'urp_i', 'uucp', 'uucp_path', 'vmnet', 'whois', 'X11', 'Z39_50', 'OTH', 'REJ', 'RSTO', 'RSTOS0', 'RSTR', 'S0', 'S1', 'S2', 'S3', 'SF', 'SH', 'src_bytes', 'dst_bytes', 'land', 'wrong_fragment','urgent', 
    'is_host_login', 'is_guest_login', 'num_shells', 'num_outbound_cmds', 'hot', 'num_failed_logins', 
    'logged_in', 'num_compromised', 'root_shell', 'su_attempted', 'num_root', 'num_file_creations', 
    'num_access_files', 'count', 'srv_count', 'serror_rate', 'srv_serror_rate', 'rerror_rate', 
    'srv_rerror_rate', 'same_srv_rate', 'diff_srv_rate', 'srv_diff_host_rate', 'dst_host_count', 
    'dst_host_srv_count', 'dst_host_same_srv_rate', 'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate', 
    'dst_host_srv_diff_host_rate', 'dst_host_serror_rate', 'dst_host_srv_serror_rate', 'dst_host_rerror_rate', 
    'dst_host_srv_rerror_rate'
]
df2.columns = column_names

# Convert the DataFrame to a list of dictionaries
rows = df2.to_dict(orient='records')

# Connect to MongoDB 
client = MongoClient('mongodb://localhost:27017/')
db2 = client['deeplearning_db']
collection2 = db2['valid_csv']

# Insert documents into the collection
collection2.insert_many(rows)

