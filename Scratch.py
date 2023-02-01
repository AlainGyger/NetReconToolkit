import subprocess
import inspect
import random


def single_ip_scan(ip_to_scan):
    current_function_name = inspect.getframeinfo(inspect.currentframe()).function  # Get the name of the current function for logging purposes
    print('%s - Entering function', current_function_name)

    result = subprocess.run(['nmap', ip_to_scan, '-p-', '-T5'], stdout=subprocess.PIPE)

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
            nmap_result_dict.update({line.split(' ')[0] + '/' + line.split(' ')[1]: line.split(' ')[2]})
        if " scanned in " in line:
            nmap_result_dict["ScanTimeSeconds"] = line.split(' ')[10]

    return nmap_result_dict


def scan_scheduler():
    # Automate when we scan an IP
    current_function_name = inspect.getframeinfo(inspect.currentframe()).function  # Get the name of the current function for logging purposes
    print('%s - Entering function', current_function_name)


def ip_slicer():
    # Nmap seems to have trouble with scanning extremely large sets of IP addresses, we'll break them up and send them one at a time
    current_function_name = inspect.getframeinfo(inspect.currentframe()).function  # Get the name of the current function for logging purposes
    print('%s - Entering function', current_function_name)


def input_sanitation():
    # Make sure there are nothing but IPs on the commandline
    current_function_name = inspect.getframeinfo(inspect.currentframe()).function  # Get the name of the current function for logging purposes
    print('%s - Entering function', current_function_name)


def write_scan_results_to_db():
    current_function_name = inspect.getframeinfo(inspect.currentframe()).function  # Get the name of the current function for logging purposes
    print('%s - Entering function', current_function_name)


def target_randomizer(list_to_shuffle):
    # Receive a target list, randomize it, and return the resulting list
    current_function_name = inspect.getframeinfo(inspect.currentframe()).function  # Get the name of the current function for logging purposes
    print('%s - Entering function', current_function_name)
    shuffled_list = list_to_shuffle
    random.shuffle(shuffled_list)
    return shuffled_list


def validate_ip(list_to_shuffle):
    # Validate that and IP is a valid IPv4 address
    current_function_name = inspect.getframeinfo(inspect.currentframe()).function  # Get the name of the current function for logging purposes
    print('%s - Entering function', current_function_name)


def ip_range_breaker():
    # Expand IP ranges into a list of individual IPs (ie. 192.168.0.0/31 = [192.168.0.0, 192.168.0.1]
    current_function_name = inspect.getframeinfo(inspect.currentframe()).function  # Get the name of the current function for logging purposes
    print('%s - Entering function', current_function_name)


if __name__ == '__main__':
    print('%s - Entering function', "Main")
    nmap_result_list = []

    ips_to_scan = ['127.0.0.1', '172.16.4.1']

    for ip in ips_to_scan:
        nmap_result_list.append(single_ip_scan(ip))

    print(nmap_result_list)
