# scanet
## Introduction
* scanet is a simple networking tool that scans IPs for open ports.
* scans a network and displays IP and MAC address of
every device connected to the network.
* gets public and private IPv4 addresses of the host.

it uses multi threading to speed up the process of port scanning, the module queue is to prevent threads
from returning duplicate results.

## Requirements
#### Modules:
* socket
* threading
* queue
* argparse
* scapy
* requests

## Usage
run `pip3 install -r requiremnets.txt`

#### examples:
to scan a port:
`python3 scanet.py scan -T 192.168.178.1 -p 80`

to scan a list of ports:
`python3 scanet.py scan -T 192.168.178.1 -p 80 443 500`

to scan a range of ports:
`python3 scanet.py scan -T 192.168.178.1 -r 1-1024`

optinal arguments:
`-t or --threads` to specify how many threads to run (default: 100)

to get a list of all devices connected to the same network: (must be given root permission!)
`python3 scanet.py local -s 192.168.178.0`

to get info, public and private IPv4 addresses:
`python3 scanet.py get general`

print help message:
`python3 scanet.py --help`
