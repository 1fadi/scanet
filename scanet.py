#!/usr/bin/python
import argparse
import socket
from threading import Thread
from queue import Queue
from sys import exit

try:
    import scapy.all as scapy
    import requests
except ModuleNotFoundError as err:
    exit("requirements not installed. \nrun: python3 -m pip install -r requirements.txt\n")

# ascii color codes
GREEN = "\033[0;32m"
RESET = "\033[0;0m"
RED = "\033[0;31m"


__version__ = "2.7"


def args_parser():
    parser = argparse.ArgumentParser(prog='PROG')
    subparser = parser.add_subparsers(dest="command")
    subparser.required = True

    parser_a = subparser.add_parser("scan", help="find open ports.")
    parser_a.add_argument("-T", "--target", dest="TARGET",
                        type=str, help="specify the target IP address",
                        required=True)
    parser_a.add_argument("-p", "--port", dest="PORTS", nargs="+",
                        type=int, help="specify one or more ports",
                        )
    parser_a.add_argument("-r", "--range", dest="RANGE",
                        type=str, help="range of ports to be scanned (e.g. 1-1024)",
                        )
    parser_a.add_argument("-t", "--threads", dest="THREADS",
                        default=100, type=int, help="number of threads (default: 100)")

    parser_b = subparser.add_parser("get", help="get info. (general, version)")
    parser_b.add_argument("info", choices=["general", "version"])

    parser_c = subparser.add_parser("local", help="scan local network.")
    parser_c.add_argument("-s", "--scan", required=True, dest="network", type=str,
                        help="scan local devices that are connected to the network.")

    return parser.parse_args()


class LocalScanner:
    """
    send ARP requests and return IPv4 + MAC address of all devices connected to the 'same' network.
    """
    def __init__(self, ip: str):
        self.ip = ip.rpartition(".")[0] + ".0"  # turn the given local ip into its network address.
        
    def arp_request(self):
        
        # verbose turned off.
        scapy.conf.verb = 0
        
        request = scapy.ARP()  # create an ARP request
        request.pdst = f"{self.ip}/24"  # specify network address in CIDR notation.

        broadcast = scapy.Ether()
        broadcast.dst = "ff:ff:ff:ff:ff:ff"

        request_broadcast = broadcast / request

        results = scapy.srp(request_broadcast, timeout=1)[0]
        return results

    def gather_info(self, data: list):
        """
        gets only necessary information from self.request() and put in list.

        :param: data: *an empty list*

        """
        try:
            results = self.request()
        except PermissionError as err:
            exit(f"{RED}Permission denied.{RESET} **root privileges needed**")

        # this section gets gateway name to get it cut from
        # hostnames which will be discovered on the network.
        gateway = self.ip.rpartition(".")[0] + ".1"
        gateway_name = socket.gethostbyaddr(gateway)

        for host in results:
            addr = host[1].psrc
            mac_addr = host[1].hwsrc
            try:
                hostname = socket.gethostbyaddr(addr)[0].replace(gateway_name[0], "").rpartition(".")[0]
                if addr == gateway:
                    hostname = "_gateway_"
            except socket.herror as err:
                hostname = "UNKOWN"
            host =  (addr, hostname, mac_addr)
            if host not in data:
                data.append(host)
        return data

    def start(self, count: int):
        """
        the main method of the class
        """
        hosts = []
        for i in range(count):
            self.gather_info(hosts)
        for host in hosts:
            print("{:16} | {:40} | {:17}".format(*host))


class PortScanner(Thread):
    def __init__(self, ip, ports):
        super().__init__()
        self.ip = ip
        self.ports = ports

    def run(self):
        while not self.ports.empty():  # it keeps looping as long as there are ports available to scan
            port = self.ports.get()
            try:
                # if a connection was successful, the port will be printed.
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # create an internet tcp sock
                sock.connect((self.ip, port))
                print(f"{GREEN} [+]{RESET} {self.ip}:{port}")
            except:
                # ports that are not open are skipped.
                continue


def fill_queue(items: list, queue_):
    for item in items:
        queue_.put(item)


def manager(number_of_threads, ip, _queue):
    """
    handling threading exceptions, 
    """
    threads = []
    for i in range(number_of_threads):  # Set how many threads to run.
        thread = PortScanner(ip, _queue)
        threads.append(thread)
    try:
        for thread in threads:
            thread.daemon = True
            thread.start()
    except (KeyboardInterrupt, SystemExit):
        exit("// debugging mode - ERROR: KeyboardInterrupt - debugging mode //")

    try:
        for thread in threads:
            thread.join()  # wait till threads finish and close.
    except KeyboardInterrupt:
        exit(f"{RED}KeyboardInterrupt.. STOPPED.{RESET}")


def ascii_banner():
    print(f"""{GREEN}
         ///              
        / SCANET 
       ///{RESET}
    """)


def extract_ipv6(hostname):
    data = socket.getaddrinfo(hostname, 80)
    exracted_data = filter(lambda x: (x[0] == socket.AF_INET6), data)  # extracts tuples that contain IPv6 addresses only
    return list(exracted_data)[0][4][0]


def main():
    args = args_parser()

    if args.command == "get":
        if args.info == "general":
            no_inet = False
            host = socket.gethostname()  # send a DNS request to get name of the host.
            ipv4 = socket.gethostbyname(host)
            # /etc/hosts file might have localhost written in it, it will return 127.0.0.1 as ipv4.
            # below is method 2 to get ipv4 but it requires an internet connection due to creating an internet socket.
            if ipv4[:3] == "127":
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # this method requires internet connection. 
                try:
                    s.connect(("8.8.8.8", 80))
                    ipv4 = s.getsockname()[0]  # return local ip of the socket.
                except:
                    no_inet = True  # not connected to a network

            if no_inet:
                ipv4 = ipv6 = gateway = "unavailable"
            else:
                ipv6 = extract_ipv6(host)
                gateway = ipv4.rpartition(".")[0] + ".1"

            try:
                public_ip = requests.get("https://ipinfo.io/json").json()["ip"]
            except:
                # if the host is not connected to the internet.
                public_ip = "unavailable"

            ascii_banner()
            print(f"""
            Hostname:     | {host}
            Gateway:      | {gateway}
            Private IPv4: | {ipv4}
            Public IPv4:  | {public_ip}
            IPv6:         | {ipv6}
            """)

        elif args.info == "version":
            global __version__
            ascii_banner()
            print("current version is:", __version__)

    elif args.command == "local":
        local_scanner = LocalScanner(args.network)
        local_scanner.start(4)

    elif args.command == "scan":
        try:
            if not args.PORTS and not args.RANGE:
                exit("[-] No ports specified! use '--help' for help")

            elif args.RANGE:
                RANGE = [int(i) for i in args.RANGE.split("-")]
                data = (args.TARGET, RANGE, args.THREADS)

            else:
                data = (args.TARGET, args.PORTS, args.THREADS)
        except:
            exit(f"{RED}[-]{RESET} Error. use '--help' or '-h' for help")

        try:
            IP, ports, threads = data  # unpacking the returning tuple of data
            try:  # check if the value is a range or a list
                ports = range(ports[0], ports[1] + 1)
            except IndexError:
                pass
            running_threads = threads  # number of threads to run
            # Queue class is to exchange data safely between multiple threads.
            # it also prevents threads from returning duplicates.
        except UnboundLocalError:
            exit(f"{RED}[-]{RESET} Error. use '--help' or '-h' for help")

        queue = Queue()
        fill_queue(ports, queue)  # it takes either a list or a range of ports
        manager(running_threads, IP, queue)
        print("\nscanning finished.\n")
    else:
        print("Invalid input. Use -h for help")


if __name__ == "__main__":
    main()
