"""
    Name: Alexandra Cyrielle L. Mangune
    Section: ETHIHAC S11

    Project Name: HOPScan (Hosts and Open Ports Scan)

    Description: HOPScan is a TCP and ICMP port scanning tool that uses the Python-NMAP and
    Scapy packages to detect live hosts and their open ports, and simulate an ICMP echo
    request.

    Source Code References:
    https://www.studytonight.com/network-programming-in-python/integrating-port-scanner-with-nmap
    https://www.programcreek.com/python/example/92225/nmap.PortScanner
    https://www.geeksforgeeks.org/python-program-to-validate-an-ip-address/
"""

# Import packages needed for this project
import nmap
import time
import argparse
import ipaddress
from argparse import RawDescriptionHelpFormatter
from scapy.layers.inet import IP, ICMP, sr1


def ping_request(host):
    """
    ICMP echo request using Scapy. A packet is sent using the sr1() function.
    If a reply is received, then the host was able to get an ICMP echo reply.
    If not, then the host was not able to get an ICMP echo reply.

    Args:
    host [str] = host/IP address

    Return:
    [str] = return a string "Y" if a reply was received and "N" otherwise
    """
    ans = sr1(IP(dst=host) / ICMP(), timeout=0.5, verbose=0)
    if ans is not None:
        return "Y"
    else:
        return "N"


def check_range(start, end):
    """
    Checks if the range is valid. The start should be greater than 0 and less than the end subnet.
    The end should be less than or equal to 255 and greater than the start subnet.

    Args:
    start [int] = starting subnet
    end [int] = end subnet

    Return:
    [bool - tuple] = returns a boolean tuple
    """
    valid_start = False
    valid_end = False
    if start >= 0 and start < end:
        valid_start = True
    if end <= 255 and end > start:
        valid_end = True
    return (valid_start, valid_end)



def main():
    """
    Main function of the program. Holds the parser and scanner of the tool.
    Args: None
    Return: None
    """
    # Parser arguments
    parser = argparse.ArgumentParser(
        description="*NOTE: nmap package for Python and the latest version of Scapy should be installed.\nsample: sudo python3 hopscan.py -sc [HOSTS]",
        formatter_class=RawDescriptionHelpFormatter)
    parser.add_argument("-v", "--version", action="store_true", help="version/about the tool")
    parser.add_argument("-sc", dest="scan", help="scan for open ports given a single/range of hosts")
    args = parser.parse_args()
    try:
        # if the user chooses to scan
        if args.scan:
            # user input host range
            hosts = args.scan
            # check if host/range of hosts is valid
            # splits the input and puts them in a list
            temp_list = hosts.split('.')
            ip_range = list(map(int,temp_list[len(temp_list)-1].split('-')))
            start = True
            end = True

            # check if a host range was inputted
            if len(ip_range) == 2:
                start, end = check_range(ip_range[0], ip_range[1])
            # if host is valid, go to the next condition
            if len(temp_list) >= 4:
                #  if range is valid, start the scan
                if start is True and end is True:
                    # start timer
                    start_time = time.time()

                    # print header
                    print(" _   _  ___  ____  ____")
                    print("| | | |/ _ \\|  _ \\/ ___|  ___ __ __ _ __")
                    print("| |_| | | | | |_) |__  \\/  __/  _  |  _  \\")
                    print("|  _  | |_| |  __/ __)  | (__| (_| | | | |")
                    print("|_| |_|\\___/|_|   |____/\\ ___\\__ __|_| |_|\n")
                    print("-" * 70)
                    print(f"\tLive Host\tICMP Echo Reply\t\tOpen Ports")
                    print("-" * 70)

                    # initialize scanner and other variables
                    nmap_scanner = nmap.PortScanner()
                    # argument simulates the terminal command 'nmap -sT --top-ports 1000'
                    arg = "-sT --top-ports 1000"
                    nmap_scanner.scan(hosts=hosts, arguments=arg)
                    # sort the host range in ascending order
                    host_sorted = sorted(nmap_scanner.all_hosts(), key=ipaddress.IPv4Address)
                    counter = 1
                    result = ""

                    # scans through the hosts
                    for host in host_sorted:
                        # formats the output to be printed
                        result =str(counter) + "\t" + host + "\t\t" + ping_request(host) + "\t\t"
                        for port in nmap_scanner[host]['tcp'].keys():
                            result = result + str(port) + "\n\t\t\t\t\t\t"
                        # prints the results
                        print(result)
                        print("-" * 70)
                        counter = counter + 1

                    # end timer
                    end_time = time.time()

                    # print total hosts scanned and total runtime
                    print(f"\nTotal hosts scanned: {len(host_sorted)}")
                    print(f"Total runtime: {(end_time-start_time)} seconds.")

                # if range is incorrect, print an error message
                else:
                    print("Range out of bounds. Please try again.")

            # if inputted host/host range is wrong, print an error message
            else:
                print("Input error. Please input a correct host/host range.")

        # if the option -v or --version was chosen, then this will print in the terminal
        elif args.version:
            print(" _   _  ___  ____  ____")
            print("| | | |/ _ \\|  _ \\/ ___|  ___ __ __ _ __")
            print("| |_| | | | | |_) |__  \\/  __/  _  |  _  \\")
            print("|  _  | |_| |  __/ __)  | (__| (_| | | | |")
            print("|_| |_|\\___/|_|   |____/\\ ___\\__ __|_| |_|\n")
            print("HOPScan (Hosts and Open Ports Scan)\n\nby Alexandra Mangune\n")
            print("HOPScan is a TCP and ICMP port scanning tool that uses Scapy to simulate an ICMP echo ")
            print("request and the Python-NMAP package to detect live hosts scan their open ports in the TCP layer.")
            print("\nThe TCP scanner makes use of the NMAP package for Python to search and scan for open hosts and ports.")
            print("\nThe ICMP echo request uses Scapy. A packet is sent using the sr1() function.")
            print("If a reply is received, then the host was able to get an ICMP echo reply; otherwise the host was not able to get an ICMP echo reply.")
        # print error message if the user did not input the correct arguments
        else:
            print("Execution error. The following arguments are required: -h, -v, -sc [hosts].")
    # if there is a keyboard interruption error, this exception will catch it and print and error message
    except KeyboardInterrupt:
        print("Keyboard Interrupt exception caught. Shutting down processes...")


if __name__ == "__main__":
    """
    Execute the main function of the project.
    Args: None
    Return: None
    """
    main()
