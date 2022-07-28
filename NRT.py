# Install imports using: pip install -r requirements.txt
import inspect
import sqlite3
import nmap
import logging
import logging.handlers

log_filename = "NetReconToolkit.log"  # The filename of the log file. TODO Set log_filename based on settings.txt
log_rotate_handler = logging.handlers.RotatingFileHandler(log_filename, maxBytes=100000, backupCount=5)  # Enable log file rotation if it exceeds maxBytes, keeping 5 total backup files. TODO Set maxBytes and backupCount via settings.txt
logging.basicConfig(format='%(asctime)s >> %(message)s', handlers=[log_rotate_handler], level=logging.DEBUG)  # Instantiate root logger. TODO Set logging level through settings.txt
logging.info('-----##### Starting NRT #####-----')


def connect_to_database():
    current_function_name = inspect.getframeinfo(inspect.currentframe()).function  # Get the name of the current function for logging purposes
    logging.info('%s - Entering function', current_function_name)

    database_name = "NetReconToolkit.db"
    sqlite3_connection = sqlite3.connect(database_name)  # Create database connection using database_name variable.
    sqlite3_connection.row_factory = sqlite3.Row  # Enable to provide index-based and case-sensitive name-based access to columns (https://docs.python.org/3/library/sqlite3.html#sqlite3.Connection.row_factory).
    return sqlite3_connection


def disconnect_from_database(sqlite3_connection):
    sqlite3_connection.close()


def scan_host(ip_to_scan):
    current_function_name = inspect.getframeinfo(inspect.currentframe()).function  # Get the name of the current function for logging purposes
    logging.info('%s - Entering function', current_function_name)

    print("Scanning: " + ip_to_scan)  # Display the host we're currently scanning.
    logging.info('%s - Scanning: %s', current_function_name, ip_to_scan)
    nmap_ps = nmap.PortScanner()  # Create our instance of python-nmap.
    nmap_ps.scan(hosts=ip_to_scan,
                 arguments='-sV -Pn -p22-445')  # Set our host to scan and arguments (sV - Service scan, Pn - don't ping, but assume the port is up, p22-445 - only scan ports 22 through 445).

    for host in nmap_ps.all_hosts():  # Iterate through all scanned hosts.
        print(nmap_ps[host].hostname())  # Display the hostname for each host.

        for protocol in nmap_ps[host].all_protocols():  # Iterate through all protocols (TCP, UDP, etc.) for one host.
            protocol_keys = nmap_ps[host][protocol].keys()  # Get a dictionary containing all port numbers (22, 80, 445, etc.) for one protocol.

            for port in protocol_keys:  # Iterate through each port in the protocol_keys dictionary.
                print(port, "-", nmap_ps[host][protocol][port]['state'])  # Display each port and it's associated state.


if __name__ == '__main__':
    logging.info('%s - Entering function', "Main")

    database_connection = connect_to_database()
    scan_host("127.0.0.1")  # The IP of the host to scan
    disconnect_from_database(database_connection)

    logging.info('-----##### Ending NRT #####-----')