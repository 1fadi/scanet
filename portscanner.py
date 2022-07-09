import socket
import threading
from queue import Queue
import argparse

# colors
GREEN = "\033[0;32m"
RESET = "\033[0;0m"
RED = "\033[0;31m"


class Scanner(threading.Thread):
    def __init__(self, ip, _queue):
        threading.Thread.__init__(self)
        self.ip = ip
        self._queue = _queue

    def run(self):
        global GREEN
        global RESET
        """
        it keeps looping as long as there are ports available to scan
        """
        while not self._queue.empty():
            port = self._queue.get()
            try:
                # if a connection was successful, the port will be printed.
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.connect((self.ip, port))
                print(f"{GREEN} [+]{RESET} {self.ip}:{port}")
            except:
                # ports that are not open are skipped.
                continue


def fill_queue(_port_range, _queue):
    for port in _port_range:
        _queue.put(port)


def manager(_range, ip, _queue):
    global RED
    global RESET
    threads = []
    for i in range(_range):  # Set how many threads to run.
        thread = Scanner(ip, _queue)
        threads.append(thread)

    for thread in threads:
        thread.start()

    try:
        for thread in threads:
            thread.join()  # wait till threads finish and close.
    except KeyboardInterrupt:
        print(f"{RED}exiting..{RESET}")


def ascii_banner():
    print("""\033[0;32m
         ///              
        / PORT SCANNER 
       ///\033[0;0m
    """)


def args_parser():
    parser = argparse.ArgumentParser()
    parser.add_argument("-T", "--target", dest="TARGET",
                        type=str, help="specify the target IP address",
                        required=True)
    parser.add_argument("-p", "--port", dest="PORTS", nargs="+",
                        type=int, help="specify one or more ports",
                        )
    parser.add_argument("-r", "--range", dest="RANGE",
                        type=str, help="range of ports to be scanned (e.g. 1-1024)",
                        )
    parser.add_argument("-t", "--threads", dest="THREADS",
                        default=100, type=int, help="number of threads (default: 100)")
    args = parser.parse_args()
    try:
        if args.RANGE:
            RANGE = [int(i) for i in args.RANGE.split("-")]
            data = (args.TARGET, RANGE, args.THREADS)
            return data
        elif not args.PORTS and not args.RANGE:
            print("[-] Error. use '--help' for help")
        else:
            data = (args.TARGET, args.PORTS, args.THREADS)
            return data
    except:
        print("[-] Error. use '--help' for help")


def main():
    ascii_banner()
    IP, ports, threads = args_parser()  # unpacking the returning tuple of data

    try:  # check if the value is a range or a list
        ports = range(ports[0], ports[1] + 1)
    except IndexError:
        pass

    running_threads = threads  # number of threads to run

    queue = Queue()
    fill_queue(ports, queue)  # it takes either a list or a range of ports
    manager(running_threads, IP, queue)

    print("\nscanning finished.\n")


if __name__ == "__main__":
    main()
