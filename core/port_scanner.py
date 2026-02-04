"""
Port Scanner Module
Handles the core port scanning functionality
"""

import socket
import threading
from queue import Queue
from datetime import datetime
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)


class PortScanner:
    """
    Main port scanner class that performs TCP port scanning
    """
    
    def __init__(self, target, ports, timeout=1, threads=100):
        """
        Initialize the port scanner
        
        Args:
            target (str): Target IP address
            ports (list): List of ports to scan
            timeout (float): Socket connection timeout
            threads (int): Number of concurrent threads
        """
        self.target = target
        self.ports = ports
        self.timeout = timeout
        self.threads = threads
        self.open_ports = []
        self.queue = Queue()
        self.lock = threading.Lock()
        
    def tcp_scan(self, port):
        """
        Perform TCP scan on a specific port
        
        Args:
            port (int): Port number to scan
            
        Returns:
            bool: True if port is open, False otherwise
        """
        try:
            # Create a socket object
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            
            # Attempt to connect
            result = sock.connect_ex((self.target, port))
            sock.close()
            
            # If connection successful, port is open
            if result == 0:
                return True
            return False
            
        except socket.gaierror:
            print(f"{Fore.RED}[-] Hostname could not be resolved{Style.RESET_ALL}")
            return False
        except socket.error:
            print(f"{Fore.RED}[-] Could not connect to server{Style.RESET_ALL}")
            return False
    
    def worker(self):
        """
        Worker thread function to process ports from queue
        """
        while True:
            port = self.queue.get()
            if port is None:
                break
                
            if self.tcp_scan(port):
                with self.lock:
                    self.open_ports.append(port)
                    print(f"{Fore.GREEN}[+] Port {port} is OPEN{Style.RESET_ALL}")
            
            self.queue.task_done()
    
    def scan(self):
        """
        Start the port scanning process
        
        Returns:
            dict: Scan results containing open ports and metadata
        """
        print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Starting scan on target: {self.target}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Ports to scan: {len(self.ports)}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Start time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}\n")
        
        start_time = datetime.now()
        
        # Create worker threads
        threads = []
        for _ in range(min(self.threads, len(self.ports))):
            t = threading.Thread(target=self.worker)
            t.daemon = True
            t.start()
            threads.append(t)
        
        # Add ports to queue
        for port in self.ports:
            self.queue.put(port)
        
        # Wait for all tasks to complete
        self.queue.join()
        
        # Stop workers
        for _ in range(len(threads)):
            self.queue.put(None)
        for t in threads:
            t.join()
        
        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()
        
        # Sort open ports
        self.open_ports.sort()
        
        # Display results
        print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}Scan completed!{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Total open ports found: {len(self.open_ports)}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Scan duration: {duration:.2f} seconds{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}\n")
        
        return {
            'target': self.target,
            'open_ports': self.open_ports,
            'total_ports_scanned': len(self.ports),
            'duration': duration,
            'start_time': start_time.strftime('%Y-%m-%d %H:%M:%S'),
            'end_time': end_time.strftime('%Y-%m-%d %H:%M:%S')
        }
    
    def get_open_ports(self):
        """
        Get list of open ports
        
        Returns:
            list: List of open port numbers
        """
        return self.open_ports