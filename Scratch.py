import subprocess

result = subprocess.run(['nmap', '127.0.0.1', '--open'], stdout=subprocess.PIPE)
nmap_scan_output_raw = result.stdout.decode('utf-8')

for line in nmap_scan_output_raw.split("\n"):
    print(line)
