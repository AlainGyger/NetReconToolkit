import ipaddress
import sqlite3
import subprocess
import inspect
import random
from ipaddress import IPv4Network
import schedule
import time
import re
from tabulate import tabulate
import socket
import netifaces


def get_all_ips():
    ip_list = []
    for interface in netifaces.interfaces():
        addrs = netifaces.ifaddresses(interface)
        for ip_version in (socket.AF_INET, socket.AF_INET6):
            ips = addrs.get(ip_version, [])
            for single_ip in ips:
                if 'addr' in single_ip:
                    ip_list.append(single_ip['addr'])
    return ip_list


def single_ip_scan(ip_to_scan):
    current_function_name = inspect.getframeinfo(inspect.currentframe()).function  # Get the name of the current function for logging purposes
    print(current_function_name + " - Entering function")

    result = subprocess.run(['nmap', ip_to_scan, '-p-', '-T5', '-Pn'], stdout=subprocess.PIPE)

    nmap_scan_output_raw = result.stdout.decode('utf-8')

    nmap_result_dict = {"HostIP": ip_to_scan, "HostName": "", "HostState": "", "HostLatencySeconds": "", "ScanTimeSeconds": ""}

    for line_with_multiple_spaces in nmap_scan_output_raw.split("\n"):  # Replace multiple spaces with one
        line = ' '.join(line_with_multiple_spaces.split())
        # print(line)
        if "Nmap scan report for" in line:
            nmap_result_dict["HostIP"] = line.split(' ')[5][1:-1]
            nmap_result_dict["HostName"] = line.split(' ')[4]
        if "Host is " in line:
            nmap_result_dict["HostState"] = line.split(' ')[2]
            nmap_result_dict["HostLatencySeconds"] = line.split(' ')[3][1:-1]
        if "Note: Host seems down." in line:
            nmap_result_dict["HostState"] = line.split(' ')[3][:-1]
        if "/tcp" in line or "/udp" in line:
            nmap_result_dict.update({line.split(' ')[1]: line.split(' ')[2] + '_' + line.split(' ')[0].replace('/', '_')})
        if " scanned in " in line:
            nmap_result_dict["ScanTimeSeconds"] = line.split(' ')[10]

    return nmap_result_dict


def scan_scheduler(interval_in_seconds):
    # Automate when we scan an IP
    current_function_name = inspect.getframeinfo(inspect.currentframe()).function  # Get the name of the current function for logging purposes
    print(current_function_name + " - Entering function")

    schedule.every(interval_in_seconds).seconds.do(single_ip_scan)

    while True:
        schedule.run_pending()
        time.sleep(1)


def ip_slicer(list_of_ips):
    # Nmap seems to have trouble with scanning extremely large sets of IP addresses, we'll break them up and send them one at a time
    current_function_name = inspect.getframeinfo(inspect.currentframe()).function  # Get the name of the current function for logging purposes
    print(current_function_name + " - Entering function")

    for single_ip in list_of_ips:
        single_ip_scan(single_ip)


def input_sanitation(input_string):
    # Make sure there are nothing but IPs on the commandline
    current_function_name = inspect.getframeinfo(inspect.currentframe()).function  # Get the name of the current function for logging purposes
    print(current_function_name + " - Entering function")

    ipv4_pattern = re.compile(r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$")
    cidr_pattern = re.compile(r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)/\d{1,2}$")
    ipv6_pattern = re.compile(r"^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:))$")
    range_pattern = re.compile(r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)-(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$")

    if ipv4_pattern.search(input_string):
        return input_string
    elif cidr_pattern.search(input_string):
        return input_string
    elif ipv6_pattern.search(input_string):
        return input_string
    elif range_pattern.search(input_string):
        return input_string
    return None

def write_scan_results_to_db():
    current_function_name = inspect.getframeinfo(inspect.currentframe()).function  # Get the name of the current function for logging purposes
    print(current_function_name + " - Entering function")


def target_randomizer(list_to_shuffle):
    # Receive a target list, randomize it, and return the resulting list
    current_function_name = inspect.getframeinfo(inspect.currentframe()).function  # Get the name of the current function for logging purposes
    print(current_function_name + " - Entering function")
    shuffled_list = list_to_shuffle
    random.shuffle(shuffled_list)
    return shuffled_list


def validate_ip(ip_to_verify):
    # Validate that and IP is a valid IPv4 address
    current_function_name = inspect.getframeinfo(inspect.currentframe()).function  # Get the name of the current function for logging purposes
    print(current_function_name + " - Entering function")

    try:
        ip_object = ipaddress.ip_address(ip_to_verify)
        return True
    except ValueError:
        return False


def ip_range_breaker(ip_range):
    # Expand IP ranges into a list of individual IPs (ie. 192.168.0.0/31 = [192.168.0.0, 192.168.0.1]
    current_function_name = inspect.getframeinfo(inspect.currentframe()).function  # Get the name of the current function for logging purposes
    print(current_function_name + " - Entering function")
    try:
        network = IPv4Network(ip_range)
        ip_range_list = []
        for individual_ip in network:
            ip_range_list.append(individual_ip)
        return ip_range_list
    finally:
        print(ip_range + " is not a valid IPv4 range.")
        exit()


def display_results_as_table(scan_result_dictionary):
    # Print the names of the columns.
    print("{:<10} {:<10} {:<10} {:<10} {:<10}".format('IP', 'NAME', 'STATE', 'LATENCY', 'SCAN_TIME'))

    # print each data item.
    for key, value in scan_result_dictionary.items():
        host_ip, host_name, host_state, host_latency_seconds, scan_time_seconds = value
        # print(value)
        print("{:<10} {:<10} {:<10}".format(host_ip, host_name, host_state))


def display_table(table_name):
    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()

    cursor.execute(f"SELECT * FROM {table_name}")
    rows = cursor.fetchall()

    for row in rows:
        print(row)

    conn.close()


def display_table_in_tabular(table_name):
    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM {table_name}")
    rows = cursor.fetchall()
    columns = [description[0] for description in cursor.description]
    print(tabulate(rows, headers=columns))
    conn.close()


def dict_to_table(data, table_name):
    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()

    keys = ", ".join(data.keys())
    values = tuple(data.values())

    cursor.execute(f"CREATE TABLE IF NOT EXISTS {table_name} ({keys})")
    cursor.execute(f"INSERT INTO {table_name} ({keys}) VALUES {values}")

    conn.commit()
    conn.close()


if __name__ == '__main__':
    print("Main - Entering function")
    for ip in get_all_ips():
        print("Your IP is: " + str(ip))
    nmap_result_list = []

    ips_to_scan = ['127.0.0.1', '1.1111.23.2']

    invalid_ips = []

    for ip in ips_to_scan:
        if validate_ip(ip) == True:
            nmap_result_list.append(single_ip_scan(ip))
            dict_to_table(nmap_result_list[0], 'results')
        else:
            invalid_ips.append(ip)


    print(nmap_result_list)
    #display_results_as_table(nmap_result_list[0])

    display_table_in_tabular('results')

    print("Invalid IPs ---- ")
    print(invalid_ips)
