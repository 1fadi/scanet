#!/usr/bin/env python
import argparse
import socket
from threading import Thread, Lock
from queue import Queue
from sys import exit, platform

try:
    import scapy.all as scapy
    import requests
except ModuleNotFoundError as err:
    exit("requirements not installed. \nrun: python3 -m pip install -r requirements.txt\n")

# ascii color codes
GREEN = "\033[0;32m"
RESET = "\033[0;0m"
RED = "\033[0;31m"


version = "2.9.1"


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
                        default=50, type=int, help="number of threads (default: 50)")

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

        results = scapy.srp(request_broadcast, timeout=1)  # return answered and unanswered requests. 
        if len(list(results[0])) == 0:  # check if no answers at all.
            exit(f"{RED}[-]{RESET} Error. No answers received.\n\
                * device might not be connected to a network.\n\
                * The specified Network address might be wrong.")
        return results[0]

    def gather_info(self, data: list):
        """
        gets only necessary information from self.request() and put in list.

        :param: data: *an empty list*

        """
        if platform == 'darwin':
            exit(f"{RED}Permission denied.{RESET} Apple device detected: Apple doesn't grant root privileges. \
                try running this program on linux in a Virtual Machine.")
        try:
            results = self.arp_request()
        except PermissionError as err:
            exit(f"{RED}Permission denied.{RESET} **root privileges needed**")

        # this section gets gateway name to get it cut from
        # hostnames which will be discovered on the network.
        gateway = self.ip.rpartition(".")[0] + ".1"
        try:
            gateway_name = socket.gethostbyaddr(gateway)
        except socket.herror:
            pass

        for host in results:
            addr = host[1].psrc
            mac_addr = host[1].hwsrc

            try:
                hostname = socket.gethostbyaddr(addr)[0]#.replace(gateway_name[0], "").rpartition(".")[0]
                if addr == gateway:
                    hostname = "_gateway_"
            except socket.herror:
                hostname = "UNKOWN"
            finally:
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
        print(f"{len(hosts)} answers recieved.\n")
        for host in hosts:
            print("{:16} | {:40} | {:17}".format(*host))


class PortScanner(Thread):
    def __init__(self, ip, ports):
        super().__init__()
        self.ip = ip
        self.ports = ports
        self.lock = Lock()

    def run(self):
        while not self.ports.empty():  # keep looping as long as there are ports available to scan
            port = self.ports.get()

            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # create an internet tcp sock
                sock.connect((self.ip, port))

            except OverflowError:
                print(f"{RED} [-] !{port}{RESET} Port must be 0-65535.")
            except (ConnectionError, ConnectionRefusedError, OSError):
                with self.lock: 
                    # skip closed ports.
                    print("scanning..", end="\r")

            else:
                # if a connection was successful, the port will be printed.
                with self.lock:  # acquire and release lock to prevent race conditions.
                    print(f"{GREEN} [+]{RESET} {self.ip}:{port}")
            finally:
                sock.close()
    

def fill_queue(items: list, queue_):
    for item in items:
        queue_.put(item)


def manager(number_of_threads, ip, _queue):
    """
    handling threading exceptions.
    """
    threads = []
    for i in range(number_of_threads):  # Set how many threads to run.
        thread = PortScanner(ip, _queue)
        threads.append(thread)
    try:
        for thread in threads:
            thread.daemon = True
            thread.start()
    except (KeyboardInterrupt, SystemExit) as err:
        exit(err)

    try:
        for thread in threads:
            thread.join()  # wait till threads finish and close.
    except KeyboardInterrupt:
        exit(f"{RED}KeyboardInterrupt.. STOPPED.{RESET}")


def ascii_banner():
    b = """
         //////-//////-//////-//--//-//////-//////
        //-----//-----//--//-///-//-//-------//
       //////-//-----//////-//////-//////---//
      ----//-//-----//--//-//-///-//-------//
     //////-//////-//--//-//--//-//////---//
    """
    r = ""
    for i in b:
        if i == "/":
            r += f"{GREEN}/{RESET}"
        else:
            r += i
    return r


def extract_ipv6(hostname):
    data = socket.getaddrinfo(hostname, 80)
    exracted_data = filter(lambda x: (x[0] == socket.AF_INET6), data)  # extracts tuples that contain IPv6 addresses only
    try:
        return list(exracted_data)[0][4][0]
    except IndexError:
        return None

def main():
    args = args_parser()

    if args.command == "get":
        if args.info == "general":
            no_inet = False
            host = socket.gethostname()  # send a DNS request to get name of the host.
            ipv4 = socket.gethostbyname(host)
            # /etc/hosts file might have localhost written in it, it will return 127.0.0.1 as ipv4.
            # below is method 2 to get ipv4 but it requires an internet connection due to creating an internet socket.
            if ipv4[:3] == "127" and (platform == 'linux' or platform == 'linux2'):
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # this method requires internet connection. 
                try:
                    s.connect(("8.8.8.8", 80))
                except (ConnectionError, OSError, ConnectionRefusedError):
                    no_inet = True  # not connected to a network
                else:
                    ipv4 = s.getsockname()[0]  # return local ip of the socket.

            if no_inet:
                ipv4 = ipv6 = gateway = "unavailable"
            else:
                ipv6 = extract_ipv6(host)
                gateway = ipv4.rpartition(".")[0] + ".1"

            try:
                public_ip = requests.get("https://ipinfo.io/json").json()["ip"]
            except requests.exceptions.ConnectionError:
                # the host is not connected to the internet.
                public_ip = "unavailable"

            print(ascii_banner())
            print(f"""
            Hostname:     | {host}
            Gateway:      | {gateway}
            Private IPv4: | {ipv4}
            Public IPv4:  | {public_ip}
            IPv6:         | {ipv6}
            """)

        elif args.info == "version":
            print(ascii_banner())
            print("current version is:", version)

    elif args.command == "local":
        try:
            socket.inet_aton(args.network)
        except socket.error:
            exit(f"{RED}[-]{RESET} The provided network IP address is invalid!")

        local_scanner = LocalScanner(args.network)
        local_scanner.start(4)

    elif args.command == "scan":
        try:
            socket.inet_aton(args.TARGET)
        except socket.error:
            exit(f"{RED}[-]{RESET} Use a valid IP address.")

        if not args.PORTS and not args.RANGE:
            exit(f"{RED}[-]{RESET} No ports specified! use '--help' for help")
        elif args.RANGE:
            try:
                RANGE = [int(i) for i in args.RANGE.split("-")]
                if len(RANGE) != 2:
                    exit(f"{RED}[-]{RESET} Invalid range of ports!") 
                ports = range(RANGE[0], RANGE[1] + 1)
            except (ValueError, IndexError):
                exit(f"{RED}[-]{RESET} Invalid range of ports!") 
            data = (args.TARGET, ports, args.THREADS)
        else:
            data = (args.TARGET, args.PORTS, args.THREADS)

        try:
            IP, ports, threads = data
            running_threads = threads  # number of threads to run
            # Queue class is to exchange data safely between multiple threads.
            # it also prevents threads from returning duplicates.
        except UnboundLocalError:
            exit(f"{RED}[-]{RESET} Error. use '--help' or '-h' for help")
        else:
            print("")
            queue = Queue()
            fill_queue(ports, queue)  # it takes either a list or a range of ports
            manager(running_threads, IP, queue)
            print("__________________________")
            print("\nProcess finished.\n")
    else:
        print("Invalid option. Use -h for help")


if __name__ == "__main__":
    main()
