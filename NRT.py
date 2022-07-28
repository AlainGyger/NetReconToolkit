# Install imports using: pip install -r requirements.txt
import inspect
import sqlite3
import nmap
import logging
import logging.handlers

log_filename = "NetReconToolkit.log"  # The filename of the log file. TODO Set log_filename based on settings.txt
log_rotate_handler = logging.handlers.RotatingFileHandler(log_filename, maxBytes=100000,
                                                          backupCount=5)  # Enable log file rotation if it exceeds maxBytes, keeping 5 total backup files. TODO Set maxBytes and backupCount via settings.txt
logging.basicConfig(format='%(asctime)s >> %(message)s', handlers=[log_rotate_handler], level=logging.DEBUG)  # Instantiate root logger. TODO Set logging level through settings.txt
logging.info('-----##### Starting NRT #####-----')

database_name = "NetReconToolkit.db"


def connect_to_database():
    current_function_name = inspect.getframeinfo(inspect.currentframe()).function  # Get the name of the current function for logging purposes
    logging.info('%s - Entering function', current_function_name)

    logging.info('%s - Started database connection', current_function_name)
    sqlite3_connection = sqlite3.connect(database_name)  # Create database connection using database_name variable.
    sqlite3_connection.row_factory = sqlite3.Row  # Enable to provide index-based and case-sensitive name-based access to columns (https://docs.python.org/3/library/sqlite3.html#sqlite3.Connection.row_factory).
    logging.info('%s - Finished database connection', current_function_name)

    return sqlite3_connection


def database_table_setup(table_name, sqlite3_connection):
    current_function_name = inspect.getframeinfo(inspect.currentframe()).function  # Get the name of the current function for logging purposes
    logging.info('%s - Entering function', current_function_name)

    cursor = sqlite3_connection.cursor()
    logging.info('%s - Checking if %s table exists', current_function_name, table_name)

    if table_name == 'HOSTS':
        list_of_tables = cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='" + table_name + "';").fetchall()
        if list_of_tables == []:  # Create the table if it does not exist (ie. the "list_of_tables" array is empty)
            logging.info('%s - %s table not found in %s ... creating it now.', current_function_name, table_name, database_name)
            with sqlite3_connection:
                sqlite3_connection.execute("""
                    CREATE TABLE """ + table_name + """ (
                        hosts_id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
                        scan_id INTEGER,
                        network_label TEXT,
                        dns TEXT,
                        ip_full TEXT,
                        ip_split1 INTEGER,
                        ip_split2 INTEGER,
                        ip_split3 INTEGER,
                        ip_split4 INTEGER,
                        create_date DATE,
                        create_time TIME,
                        create_datetime DATETIME,
                        UNIQUE(dns, ip_full)
                    );
                """)
        else:  # The "list_of_tables" is not empty, which only happens when there is a table in the DB with a name of "HOSTS"
            logging.info('%s - %s table found in %s ... not re-creating it!', current_function_name, table_name, database_name)
            print("Checking table for correct columns in correct order ...")
            table_columns = cursor.execute("SELECT * FROM HOSTS").fetchone()
            print(table_columns[0])

    if table_name == 'PORTS':
        list_of_tables = cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='" + table_name + "';").fetchall()
        if list_of_tables == []:
            logging.info('%s - %s table not found in %s ... creating it now.', current_function_name, table_name, database_name)
            with sqlite3_connection:
                sqlite3_connection.execute("""
                    CREATE TABLE """ + table_name + """ (
                        ports_id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
                        scan_id INTEGER,
                        network_label TEXT,
                        dns TEXT,
                        ip TEXT,
                        protocol TEXT,
                        port INTEGER,
                        state TEXT,
                        reason TEXT,
                        name TEXT,
                        product TEXT,
                        version TEXT,
                        extra_info TEXT,
                        confidence TEXT,
                        common_platform_enumeration TEXT,
                        start_scan_datetime DATETIME
                    );
                """)
        else:
            logging.info('%s - %s table found in %s ... not re-creating it!', current_function_name, table_name, database_name)


def disconnect_from_database(sqlite3_connection):
    current_function_name = inspect.getframeinfo(inspect.currentframe()).function  # Get the name of the current function for logging purposes
    logging.info('%s - Entering function', current_function_name)

    logging.info('%s - Committing any remaining transactions to database', current_function_name)
    sqlite3_connection.commit()

    logging.info('%s - Closing database connection', current_function_name)
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

    database_connection = connect_to_database()  # Save the database connection as a variable, so we can use it later.
    database_table_setup("HOSTS", database_connection)
    database_table_setup("PORTS", database_connection)
    scan_host("127.0.0.1")  # The IP of the host to scan
    disconnect_from_database(database_connection)  # Pass the currently open database connection variable to close the connection.

    logging.info('-----##### Ending NRT #####-----')
