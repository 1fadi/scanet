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

## TARGET IP ##
IP = "192.168.178.1"
# IP = "localhost"
port_range = range(1, 62115)  # or create a list instead

queue = Queue()


def portscanner():
    while not queue.empty():
        port = queue.get()
        try:
            # it a connection was successfull, the port will be printed.
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((target, port))
            print(f"{GREEN} [+]{RESET} {target}:{port}")
        except:
            # ports that are not open are skipped.
            continue


def fill_queue(port_range):
    for port in port_range:
        queue.put(port)

        
fill_queue(port_range)
threads = []

for i in range(100):  # Set how many threads to run.
    thread = threading.Thread(target=portscanner)
    threads.append(thread)

for i in threads:
    i.start()

try:
    for thread in threads:
        thread.join()  # wait till threads finish and close.
except KeyboardInterrupt:
    print(f"{RED}exiting..{RESET}")

print("\nscanning finished.\n")
