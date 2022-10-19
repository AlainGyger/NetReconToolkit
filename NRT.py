# Install imports using: pip install -r requirements.txt
import argparse
import datetime
import inspect
import sqlite3
import sys

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
    try:
        sqlite3_connection = sqlite3.connect(database_name)  # Create database connection using database_name variable.
        sqlite3_connection.row_factory = sqlite3.Row  # Enable to provide index-based and case-sensitive name-based access to columns (https://docs.python.org/3/library/sqlite3.html#sqlite3.Connection.row_factory). The line of code assigning sqlite3.Row to the row_factory of connection creates what some people call a 'dictionary cursor', - instead of tuples it starts returning 'dictionary' rows after fetchall or fetchone.
        logging.info('%s - Finished database connection', current_function_name)
    except:
        logging.info('%s - Database connection failed', current_function_name)

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
            # print("Checking table for correct columns in correct order ...")
            # table_columns = cursor.execute("SELECT * FROM HOSTS").fetchone()
            # print(table_columns[0])

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


def scan_host(sqlite3_connection, arguments_dictionary):
    current_function_name = inspect.getframeinfo(inspect.currentframe()).function  # Get the name of the current function for logging purposes
    logging.info('%s - Entering function', current_function_name)
    scan_id = ""
    network_label = ""
    target = arguments_dictionary["target"]

    print("Scanning: " + target)  # Display the host we're currently scanning.
    logging.info('%s - Scanning: %s', current_function_name, target)
    scan_start_time = datetime.datetime.now()
    nmap_ps = nmap.PortScanner()  # Create our instance of python-nmap.
    nmap_ps.scan(hosts=target,
                 arguments='-sV -Pn -p22-445')  # Set our host to scan and arguments (sV - Service scan, Pn - don't ping, but assume the port is up, p22-445 - only scan ports 22 through 445).

    for host in nmap_ps.all_hosts():  # Iterate through all scanned hosts.
        print(nmap_ps[host].hostname())  # Display the hostname for each host.

        for protocol in nmap_ps[host].all_protocols():  # Iterate through all protocols (TCP, UDP, etc.) for one host.
            protocol_keys = nmap_ps[host][protocol].keys()  # Get a dictionary containing all port numbers (22, 80, 445, etc.) for one protocol.

            for port in protocol_keys:  # Iterate through each port in the protocol_keys dictionary.
                print(port, "-", nmap_ps[host][protocol][port]['state'])  # Display each port and it's associated state.

    for host in nmap_ps.all_hosts():
        sql = 'INSERT OR IGNORE INTO HOSTS (scan_id, network_label, dns, ip_full, ip_split1, ip_split2, ip_split3, ip_split4, create_date, create_time, create_datetime) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);'
        data = [
            (scan_id, network_label, nmap_ps[host].hostname(), host, host.split(".")[0], host.split(".")[1], host.split(".")[2], host.split(".")[3], scan_start_time.strftime('%Y-%m-%d'),
             scan_start_time.strftime('%H:%M:%S'),
             scan_start_time.strftime('%Y-%m-%d %H:%M:%S'))
        ]
        with sqlite3_connection:
            sqlite3_connection.executemany(sql, data)

        for proto in nmap_ps[host].all_protocols():
            protocol_keys = nmap_ps[host][proto].keys()
            for port in protocol_keys:
                sql = 'INSERT OR IGNORE INTO PORTS (scan_id, network_label, dns, ip, protocol, port, state, reason, name, product, version, extra_info, confidence, common_platform_enumeration, start_scan_datetime) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);'
                data = [
                    (scan_id, network_label, nmap_ps[host].hostname(), host, proto, port, nmap_ps[host][proto][port]['state'], nmap_ps[host][proto][port]['reason'], nmap_ps[host][proto][port]['name'],
                     nmap_ps[host][proto][port]['product'],
                     nmap_ps[host][proto][port]['version'], nmap_ps[host][proto][port]['extrainfo'], nmap_ps[host][proto][port]['conf'], nmap_ps[host][proto][port]['cpe'],
                     scan_start_time.strftime('%Y-%m-%d %H:%M:%S'))]
                with sqlite3_connection:
                    sqlite3_connection.executemany(sql, data)


def read_database_tables(sqlite3_connection):
    cursor_obj = sqlite3_connection.cursor()

    print("----- HOSTS -----")
    statement = "SELECT * FROM HOSTS"
    cursor_obj.execute(statement)
    output = cursor_obj.fetchall()
    for row in output:
        print(f"{row['hosts_id']}, {row['dns']}, {row['ip_full']}, {row['create_datetime']}")

    print("")
    print("----- PORTS -----")
    statement = "SELECT * FROM PORTS"
    cursor_obj.execute(statement)
    output = cursor_obj.fetchall()
    for row in output:
        print(f"{row['ports_id']}, {row['dns']}, {row['ip']}, {row['protocol']}, {row['port']}, {row['state']}, {row['reason']}, {row['name']}, {row['product']}, {row['version']}")


def collect_user_arguments():
    current_function_name = inspect.getframeinfo(inspect.currentframe()).function  # Get the name of the current function for logging purposes
    logging.info('%s - Entering function', current_function_name)

    # If a user doesn't give a command line parameter, the use interactive mode
    if len(sys.argv) > 1:  # The first argument is considered the command itself. Any additional arguments begin at 2.
        logging.debug('%s - %s command line arguments given: %s', current_function_name, str(len(sys.argv) - 1), sys.argv)
        argument_parser = argparse.ArgumentParser(description='A wrapper for NMap intended to create a light-weight network information gathering toolkit.')
        argument_parser.add_argument('target', metavar='Target', type=str, help='The target IP to scan.')  # TODO Add an "Own IP" option to automatically get computer's IP and use it as the target
        arguments = argument_parser.parse_args()
        arguments_dictionary = {"target": arguments.target}
    else:  # No arguments have been given, use interactive mode.
        logging.debug('%s - No command line arguments given: %s', current_function_name, sys.argv)
        target = str(input("Type an IP to scan in the form x.x.x.x: "))
        logging.debug('%s - Interactive target argument given: %s', current_function_name, target)
        arguments_dictionary = {"target": target}
    return arguments_dictionary


if __name__ == '__main__':
    logging.info('%s - Entering function', "Main")

    database_connection = connect_to_database()  # Save the database connection as a variable, so we can use it later.
    database_table_setup("HOSTS", database_connection)
    database_table_setup("PORTS", database_connection)
    #user_arguments_dictionary = collect_user_arguments()
    #scan_host(database_connection, user_arguments_dictionary)  # The IP of the host to scan
    read_database_tables(database_connection)
    disconnect_from_database(database_connection)  # Pass the currently open database connection variable to close the connection.

    logging.info('-----##### Ending NRT #####-----')
