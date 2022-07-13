import nmap  # install python-nmap


def scan_host(ip_to_scan):
    print("Scanning: " + ip_to_scan)  # Display the host we're currently scanning
    nmap_ps = nmap.PortScanner()  # Create our instance of python-nmap
    nmap_ps.scan(hosts=ip_to_scan,
                 arguments='-sV -Pn -p22-445')  # Set our host to scan and arguments (sV - Service scan, Pn - don't ping, but assume the port is up, p22-445 - only scan ports 22 through 445)

    for host in nmap_ps.all_hosts():  # Iterate through all scanned hosts
        print(nmap_ps[host].hostname())  # Display the hostname for each host

        for protocol in nmap_ps[host].all_protocols():  # Iterate through all protocols (TCP, UDP, etc.) for one host
            protocol_keys = nmap_ps[host][protocol].keys()  # Get a dictionary containing all port numbers (22, 80, 445, etc.) for one protocol

            for port in protocol_keys:  # Iterate through each port in the protocol_keys dictionary
                print(port, "-", nmap_ps[host][protocol][port]['state'])  # Display each port and it's associated state


if __name__ == '__main__':
    scan_host("127.0.0.1")  # The IP of the host to scan
