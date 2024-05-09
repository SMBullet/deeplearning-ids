# Deep Learning IDS
## El Jakani 
```
@attribute 'duration' real
@attribute 'protocol_type' {'tcp','udp', 'icmp'}  Done !!
@attribute 'service' {'aol', 'auth', 'bgp', 'courier', 'csnet_ns', 'ctf', 'daytime', 'discard', 'domain', 'domain_u', 'echo', 'eco_i', 'ecr_i', 'efs', 'exec', 'finger', 'ftp', 'ftp_data', 'gopher', 'harvest', 'hostnames', 'http', 'http_2784', 'http_443', 'http_8001', 'imap4', 'IRC', 'iso_tsap', 'klogin', 'kshell', 'ldap', 'link', 'login', 'mtp', 'name', 'netbios_dgm', 'netbios_ns', 'netbios_ssn', 'netstat', 'nnsp', 'nntp', 'ntp_u', 'other', 'pm_dump', 'pop_2', 'pop_3', 'printer', 'private', 'red_i', 'remote_job', 'rje', 'shell', 'smtp', 'sql_net', 'ssh', 'sunrpc', 'supdup', 'systat', 'telnet', 'tftp_u', 'tim_i', 'time', 'urh_i', 'urp_i', 'uucp', 'uucp_path', 'vmnet', 'whois', 'X11', 'Z39_50'}  Done !!
@attribute 'flag' { 'OTH', 'REJ', 'RSTO', 'RSTOS0', 'RSTR', 'S0', 'S1', 'S2', 'S3', 'SF', 'SH' }  Done !!
@attribute 'src_bytes' real  Done !!
@attribute 'dst_bytes' real  Done !!
@attribute 'land' {'0', '1'}  Done !!
@attribute 'wrong_fragment' real  Done !!
@attribute 'urgent' real  Done !!
@attribute 'hot' real  Done by Saad !!
@attribute 'num_failed_logins' real Done by Saad and need to be discussed !!
@attribute 'logged_in' {'0', '1'}  Done by Saad and need to be discussed !!
@attribute 'num_compromised' real  Done by Saad and need to be discussed !!
@attribute 'root_shell' real   Done by Saad and need to be discussed !!
@attribute 'su_attempted' real  Done by Saad !!
@attribute 'num_root' real  Done by Saad !
@attribute 'num_file_creations' real  Done By Saad need a check !! 
@attribute 'num_shells' real Done by Saad !
@attribute 'num_access_files' real Done by Saad !
@attribute 'num_outbound_cmds' real
@attribute 'is_host_login' {'0', '1'} Done by Saad but need to be discussed !
@attribute 'is_guest_login' {'0', '1'} Done by Saad but need to be discussed !
@attribute 'count' real  Done by Saad !
@attribute 'srv_count' real  Done by Saad !
```
## Benmouya
-----------------------------------------
```
@attribute 'serror_rate' real
@attribute 'srv_serror_rate' real
@attribute 'rerror_rate' real
@attribute 'srv_rerror_rate' real
@attribute 'same_srv_rate' real
@attribute 'diff_srv_rate' real
@attribute 'srv_diff_host_rate' real
@attribute 'dst_host_count' real
@attribute 'dst_host_srv_count' real
@attribute 'dst_host_same_srv_rate' real
@attribute 'dst_host_diff_srv_rate' real
@attribute 'dst_host_same_src_port_rate' real
@attribute 'dst_host_srv_diff_host_rate' real
@attribute 'dst_host_serror_rate' real
@attribute 'dst_host_srv_serror_rate' real
@attribute 'dst_host_rerror_rate' real
@attribute 'dst_host_srv_rerror_rate' real
```