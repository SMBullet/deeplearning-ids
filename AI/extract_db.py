from pymongo import MongoClient
import csv

# Connect to MongoDB
client = MongoClient('mongodb://localhost:27017/')
db = client['deeplearning_db']
collection = db['valid_packets']


# Retrieve documents from the collection
documents = collection.find()

# Your desired field order
desired_order = ['duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes', 'land', 'wrong_fragment','urgent', 'is_host_login', 'is_guest_login', 'num_shells', 'num_outbound_cmds', 'hot', 'num_failed_logins', 'logged_in', 'num_compromised', 'root_shell', 'su_attempted', 'num_root', 'num_file_creations', 'num_access_files', 'count', 'srv_count', 'serror_rate', 'srv_serror_rate', 'rerror_rate', 'srv_rerror_rate', 'same_srv_rate', 'diff_srv_rate', 'srv_diff_host_rate', 'dst_host_count', 'dst_host_srv_count', 'dst_host_same_srv_rate', 'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate', 'dst_host_srv_diff_host_rate', 'dst_host_serror_rate', 'dst_host_srv_serror_rate', 'dst_host_rerror_rate', 'dst_host_srv_rerror_rate']

# Open a CSV file for writing
with open('data.csv', 'w', newline='') as csvfile:
    writer = csv.writer(csvfile)

    # Write the header row with the desired field order
    writer.writerow(desired_order)

    # Write each filtered document to the CSV file
    for document in documents:
        row = [document.get(field, 0) for field in desired_order]
        writer.writerow(row)
        
