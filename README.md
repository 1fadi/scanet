# Port_Scan
a script that scans for open ports

it uses multi threading to speed up the process, the module queue is to prevent threads
from returning duplicate results.

## Requirements
#### Modules:
* socket
* threading
* queue
* argparse

## Usage
####examples:
to scan a port:
`python3 portscanner.py -T 192.168.178.1 -p 80`

to scan a list of ports:
`python3 portscanner.py -T 192.168.178.1 -p 80 443 500`

to scan a range of ports:
`python3 portscanner.py -T 192.168.178.1 -r 1-1024`

optinal arguments:
`-t or --threads` to specify how many threads to run (default: 100)
print help message:
`python3 portscanner.py --help`

it can scan public and private IP addresses.
