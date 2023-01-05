import subprocess

ip_to_scan = '8.8.8.8'
result = subprocess.run(['nmap', ip_to_scan, '-p-', '-T5'], stdout=subprocess.PIPE)
nmap_scan_output_raw = result.stdout.decode('utf-8')

nmap_result_list = []
nmap_result_dict = {"HostIP": ip_to_scan, "HostName": "", "HostState": "", "HostLatencySeconds": "", "ScanTimeSeconds": ""}

for line_with_multiple_spaces in nmap_scan_output_raw.split("\n"):  # Replace multiple spaces with one
    line = ' '.join(line_with_multiple_spaces.split())
    print(line)
    if "Nmap scan report for" in line:
        nmap_result_dict["HostIP"] = line.split(' ')[5][1:-1]
        nmap_result_dict["HostName"] = line.split(' ')[4]
    if "Host is " in line:
        nmap_result_dict["HostState"] = line.split(' ')[2]
        nmap_result_dict["HostLatencySeconds"] = line.split(' ')[3][1:-1]
    if "Note: Host seems down." in line:
        nmap_result_dict["HostState"] = line.split(' ')[3][:-1]
    if "/tcp" in line or "/udp" in line:
        nmap_result_dict.update({line.split(' ')[0] + '/' + line.split(' ')[1]: line.split(' ')[2]})
    if " scanned in " in line:
        nmap_result_dict["ScanTimeSeconds"] = line.split(' ')[10]


print(nmap_result_dict)
