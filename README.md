# HOPScan: Network Discovery Tool
HOPScan (Hosts and Open Ports Scan) is a TCP and ICMP port scanning tool that uses the Python-NMAP and
Scapy packages to detect live hosts and their open ports, and simulate an ICMP echo request.

## How to Install (macOS / Linux)
In the terminal, run the following commands:
- `git clone https://github.com/lexcyman/Network-Discovery-Tool.git`
- `cd Network-Discovery-Tool`
- `sudo python3 hopscan.py -h` [view the list of commands for the tool]

## Packages Needed
The following packages are needed to run the tool:
- Python 3 [https://www.python.org/downloads/]
- NMAP (for Python) [`sudo pip3 install nmap`]
- Scapy (latest version) [`sudo pip3 install scapy`]