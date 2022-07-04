import socket
import threading
from pyfiglet import figlet_format
from queue import Queue
from colorama import Fore

# colors
GREEN = Fore.GREEN
RESET = Fore.RESET
RED = Fore.RED

ascii_banner = figlet_format("Port scanner")
print(f"{GREEN}{str(ascii_banner)}{RESET}")

# TARGET IP
IP = "192.168.178.1"
# IP = "localhost"
port_range = range(1, 62115)  # or create a list instead

queue = Queue()


class Scanner(threading.Thread):
    def __int__(self):
        threading.Thread.__init__(self)
        self.IP = IP

    def run(self):
        """
        it keeps looping as long as there are ports available to scan
        """
        global queue
        global IP
        while not queue.empty():
            port = queue.get()
            try:
                # if a connection was successful, the port will be printed.
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.connect((IP, port))
                print(f"{GREEN} [+]{RESET} {IP}:{port}")
            except:
                # ports that are not open are skipped.
                continue


def fill_queue(port_range):
    for port in port_range:
        queue.put(port)


def manager(n):  # Set how many threads to run.
    threads = []
    for i in range(n):
        thread = Scanner()
        threads.append(thread)

    for thread in threads:
        thread.start()

    try:
        for thread in threads:
            thread.join()  # wait till threads finish and close.
    except KeyboardInterrupt:
        print(f"{RED}exiting..{RESET}")


fill_queue(port_range)
manager(100)

print("\nscanning finished.\n")
