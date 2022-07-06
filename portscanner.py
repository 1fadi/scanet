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

# TARGET
IP = input("\nEnter target IP: ")
port_range = range(1, 62115)  # or create a list instead
running_threads = int(input("Enter number of threads to run: "))

queue = Queue()


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


if __name__ == "__main__":
    fill_queue(port_range, queue)
    manager(running_threads, IP, queue)

    print("\nscanning finished.\n")