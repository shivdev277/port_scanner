"""
╔══════════════════════════════════════════════════════════════════╗
║  Advanced Port Scanner Module                                    ║
║  High-performance TCP port scanning with ThreadPoolExecutor      ║
║                                                                  ║
║  WARNING: This tool is for EDUCATIONAL and AUTHORIZED testing    ║
║  only. Unauthorized scanning of networks is ILLEGAL.             ║
╚══════════════════════════════════════════════════════════════════╝
"""

import socket
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)


class PortScanner:
    """
    Advanced TCP Port Scanner with multithreading support.
    Scans ports 1-65535 (or custom range) using ThreadPoolExecutor
    for maximum performance. Supports progress callbacks for GUI integration.
    """

    def __init__(self, target, ports=None, timeout=1.0, threads=100):
        """
        Initialize the port scanner.

        Args:
            target (str): Target IP address or hostname
            ports (list): List of port numbers to scan (default: 1-65535)
            timeout (float): Socket connection timeout in seconds
            threads (int): Number of concurrent scanning threads
        """
        self.target = target
        self.ports = ports if ports else list(range(1, 65536))
        self.timeout = timeout
        self.threads = threads
        self.open_ports = []
        self.lock = threading.Lock()
        self._stop_event = threading.Event()

        # Callbacks for GUI/progress integration
        self._on_port_found = None      # Called when an open port is found
        self._on_progress = None        # Called to report scan progress
        self._on_complete = None        # Called when scan completes

    # ──────────────────────────────────────────────────────────────
    #  Callback setters (used by GUI to hook into scanner events)
    # ──────────────────────────────────────────────────────────────
    def set_on_port_found(self, callback):
        """Set callback: callback(port)  — fired when an open port is discovered."""
        self._on_port_found = callback

    def set_on_progress(self, callback):
        """Set callback: callback(scanned, total)  — fired after each port check."""
        self._on_progress = callback

    def set_on_complete(self, callback):
        """Set callback: callback(results_dict)  — fired when scan finishes."""
        self._on_complete = callback

    def stop(self):
        """Signal all workers to stop scanning (used by GUI Stop button)."""
        self._stop_event.set()

    @property
    def is_stopped(self):
        return self._stop_event.is_set()

    # ──────────────────────────────────────────────────────────────
    #  Core scanning logic
    # ──────────────────────────────────────────────────────────────
    def tcp_scan(self, port):
        """
        Perform a TCP connect scan on a single port.

        Args:
            port (int): Port number to scan

        Returns:
            int or None: The port number if open, else None
        """
        if self._stop_event.is_set():
            return None

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((self.target, port))
            sock.close()

            if result == 0:
                return port
            return None

        except socket.gaierror:
            return None
        except socket.error:
            return None
        except Exception:
            return None

    def scan(self):
        """
        Start the port scanning process using ThreadPoolExecutor.

        Returns:
            dict: Scan results containing open ports and metadata
        """
        self._stop_event.clear()
        self.open_ports = []
        scanned_count = 0
        total_ports = len(self.ports)

        print(f"\n{Fore.CYAN}{'═' * 60}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}  Target       : {self.target}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}  Ports        : {total_ports}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}  Threads      : {self.threads}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}  Timeout      : {self.timeout}s{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}  Start Time   : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'═' * 60}{Style.RESET_ALL}\n")

        start_time = datetime.now()

        # Use ThreadPoolExecutor for fast, managed concurrency
        num_workers = min(self.threads, total_ports)
        with ThreadPoolExecutor(max_workers=num_workers) as executor:
            # Submit all port scan tasks
            future_to_port = {
                executor.submit(self.tcp_scan, port): port
                for port in self.ports
            }

            for future in as_completed(future_to_port):
                if self._stop_event.is_set():
                    executor.shutdown(wait=False, cancel_futures=True)
                    break

                scanned_count += 1
                result = future.result()

                if result is not None:
                    with self.lock:
                        self.open_ports.append(result)
                    print(f"  {Fore.GREEN}[+] Port {result} is OPEN{Style.RESET_ALL}")
                    if self._on_port_found:
                        self._on_port_found(result)

                # Report progress every 500 ports or at the end
                if self._on_progress and (scanned_count % 500 == 0 or scanned_count == total_ports):
                    self._on_progress(scanned_count, total_ports)

        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()

        # Sort open ports
        self.open_ports.sort()

        # Display summary
        print(f"\n{Fore.CYAN}{'═' * 60}{Style.RESET_ALL}")
        print(f"  {Fore.GREEN}Scan completed!{Style.RESET_ALL}")
        print(f"  {Fore.YELLOW}Open ports     : {len(self.open_ports)}{Style.RESET_ALL}")
        print(f"  {Fore.YELLOW}Scanned        : {scanned_count}/{total_ports}{Style.RESET_ALL}")
        print(f"  {Fore.YELLOW}Duration       : {duration:.2f} seconds{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'═' * 60}{Style.RESET_ALL}\n")

        results = {
            'target': self.target,
            'open_ports': self.open_ports,
            'total_ports_scanned': scanned_count,
            'duration': duration,
            'start_time': start_time.strftime('%Y-%m-%d %H:%M:%S'),
            'end_time': end_time.strftime('%Y-%m-%d %H:%M:%S')
        }

        if self._on_complete:
            self._on_complete(results)

        return results

    def get_open_ports(self):
        """Return the sorted list of open ports found so far."""
        return sorted(self.open_ports)
        return self.open_ports