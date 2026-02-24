"""
╔══════════════════════════════════════════════════════════════════╗
║  Advanced Service & Version Detection Module                     ║
║  Protocol-specific banner grabbing like Nmap                     ║
║                                                                  ║
║  WARNING: This tool is for EDUCATIONAL and AUTHORIZED testing    ║
║  only. Unauthorized scanning of networks is ILLEGAL.             ║
╚══════════════════════════════════════════════════════════════════╝
"""

import socket
import ssl
import json
import os
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import Fore, Style


# ──────────────────────────────────────────────────────────────────
#  Protocol-specific probe payloads for smarter banner grabbing
# ──────────────────────────────────────────────────────────────────
PROTOCOL_PROBES = {
    # HTTP – send a HEAD request
    'http': b'HEAD / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: AdvancedScanner/2.0\r\nAccept: */*\r\nConnection: close\r\n\r\n',
    # FTP – just connect and read the banner
    'ftp': None,
    # SSH – just connect and read the banner
    'ssh': None,
    # SMTP – connect and read 220 greeting, then EHLO
    'smtp': b'EHLO scanner\r\n',
    # POP3 – connect and read +OK banner
    'pop3': None,
    # IMAP – connect and read * OK banner
    'imap': None,
    # MySQL – connect and read handshake
    'mysql': None,
    # Redis – send PING
    'redis': b'PING\r\n',
    # MongoDB – ismaster command (wire protocol)
    'mongo': None,
    # Telnet – just receive
    'telnet': None,
    # Generic – try HTTP HEAD
    'generic': b'HEAD / HTTP/1.0\r\n\r\n',
}

# Map port numbers to the probe type to use
PORT_PROBE_MAP = {
    21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp',
    80: 'http', 110: 'pop3', 143: 'imap', 443: 'http',
    465: 'smtp', 587: 'smtp', 993: 'imap', 995: 'pop3',
    3306: 'mysql', 3307: 'mysql', 6379: 'redis',
    8000: 'http', 8080: 'http', 8443: 'http', 8888: 'http',
    8081: 'http', 9090: 'http', 9200: 'http',
    27017: 'mongo',
}


class ServiceDetector:
    """
    Advanced service and version detector.
    Uses protocol-specific probes and banner grabbing
    to identify services and extract version strings.
    """

    def __init__(self):
        """Load the service database from services.json."""
        self.services_db = self._load_services_db()

    # ──────────────────────────────────────────────────────────────
    #  Service database loading
    # ──────────────────────────────────────────────────────────────
    def _load_services_db(self):
        """Load port→service mappings from the JSON data file."""
        db_path = os.path.join(os.path.dirname(__file__), '..', 'data', 'services.json')
        try:
            with open(db_path, 'r') as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return self._get_default_services()

    def _get_default_services(self):
        """Fallback minimal mappings when JSON file is unavailable."""
        return {
            "21": {"service": "FTP", "description": "File Transfer Protocol"},
            "22": {"service": "SSH", "description": "Secure Shell"},
            "23": {"service": "Telnet", "description": "Telnet"},
            "25": {"service": "SMTP", "description": "Simple Mail Transfer Protocol"},
            "53": {"service": "DNS", "description": "Domain Name System"},
            "80": {"service": "HTTP", "description": "Hypertext Transfer Protocol"},
            "110": {"service": "POP3", "description": "Post Office Protocol v3"},
            "135": {"service": "MSRPC", "description": "Microsoft RPC / DCOM"},
            "139": {"service": "NetBIOS-SSN", "description": "NetBIOS Session Service"},
            "143": {"service": "IMAP", "description": "Internet Message Access Protocol"},
            "443": {"service": "HTTPS", "description": "HTTP Secure (SSL/TLS)"},
            "445": {"service": "Microsoft-DS", "description": "Microsoft Directory Services (SMB/CIFS)"},
            "3306": {"service": "MySQL", "description": "MySQL Database"},
            "3389": {"service": "RDP", "description": "Remote Desktop Protocol"},
            "5432": {"service": "PostgreSQL", "description": "PostgreSQL Database"},
            "6379": {"service": "Redis", "description": "Redis Database"},
            "8080": {"service": "HTTP-Proxy", "description": "HTTP Proxy / Tomcat"},
            "27017": {"service": "MongoDB", "description": "MongoDB Database"},
        }

    def get_service_name(self, port):
        """
        Look up the known service name for a port.

        Args:
            port (int): Port number

        Returns:
            tuple: (service_name, description)
        """
        port_str = str(port)
        if port_str in self.services_db:
            entry = self.services_db[port_str]
            return entry['service'], entry['description']
        # Fallback: try Python's built-in socket lookup
        try:
            name = socket.getservbyport(port, 'tcp')
            return name.upper(), ''
        except (OSError, socket.error):
            return 'Unknown', ''

    # ──────────────────────────────────────────────────────────────
    #  Banner grabbing – the core of version detection
    # ──────────────────────────────────────────────────────────────
    def grab_banner(self, target, port, timeout=3):
        """
        Grab a banner from an open port using protocol-specific probes.

        1. Connect to the target:port
        2. Send an appropriate protocol probe (or none for passive grabs)
        3. Receive the response and return it as a string

        Args:
            target (str): Target IP address
            port (int): Port number
            timeout (int): Socket timeout in seconds

        Returns:
            str or None: Banner text, or None if nothing received
        """
        probe_type = PORT_PROBE_MAP.get(port, 'generic')
        probe_data = PROTOCOL_PROBES.get(probe_type, PROTOCOL_PROBES['generic'])

        # For HTTP probes, inject the host header
        if probe_data and b'{host}' in probe_data:
            probe_data = probe_data.replace(b'{host}', target.encode())

        use_ssl = port in (443, 465, 636, 853, 990, 993, 995, 8443, 9443)

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((target, port))

            # Wrap in SSL if needed
            if use_ssl:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                sock = context.wrap_socket(sock, server_hostname=target)

            # ── Passive grab (SSH, FTP, Telnet, etc. send banner first) ──
            if probe_data is None:
                banner = sock.recv(1024)
            else:
                # ── Active probe ──
                # First try to read anything the service sends immediately
                try:
                    sock.settimeout(1.5)
                    initial = sock.recv(1024)
                    if initial:
                        sock.close()
                        return initial.decode('utf-8', errors='ignore').strip()
                except socket.timeout:
                    pass

                # Send the probe
                sock.settimeout(timeout)
                sock.send(probe_data)
                banner = sock.recv(4096)

            sock.close()

            if banner:
                return banner.decode('utf-8', errors='ignore').strip()
            return None

        except ssl.SSLError:
            # If SSL handshake works but read fails, we still know it's SSL/TLS
            return "SSL/TLS service detected"
        except socket.timeout:
            return None
        except ConnectionRefusedError:
            return None
        except Exception:
            return None

    # ──────────────────────────────────────────────────────────────
    #  Version extraction from banners
    # ──────────────────────────────────────────────────────────────
    @staticmethod
    def extract_version(banner):
        """
        Parse a raw banner string and try to extract a human-readable
        service version (like 'OpenSSH 8.9p1' or 'Apache/2.4.54').

        Args:
            banner (str): Raw banner text

        Returns:
            str: Extracted version string, or the first meaningful line
        """
        if not banner:
            return "Version Unknown"

        banner_lower = banner.lower()

        # SSH – e.g. "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1"
        if banner_lower.startswith('ssh-'):
            parts = banner.split(' ')
            version_part = banner.split('-', 2)
            if len(version_part) >= 3:
                return version_part[2].split('\r')[0].split('\n')[0].strip()

        # HTTP Server header
        server_match = re.search(r'[Ss]erver:\s*(.+)', banner)
        if server_match:
            return server_match.group(1).strip()

        # FTP – "220 (vsFTPd 3.0.5)" or "220 ProFTPD 1.3.8"
        ftp_match = re.search(r'220[\s-]+(.*)', banner)
        if ftp_match and ('ftp' in banner_lower or '220' in banner):
            return ftp_match.group(1).strip().strip('()')

        # SMTP – "220 mail.example.com ESMTP Postfix"
        smtp_match = re.search(r'220\s+\S+\s+(.*)', banner)
        if smtp_match and 'smtp' in banner_lower:
            return smtp_match.group(1).strip()

        # MySQL – version bytes appear after initial handshake bytes
        mysql_match = re.search(r'(\d+\.\d+\.\d+[\w\-.]*)', banner)
        if mysql_match and ('mysql' in banner_lower or 'mariadb' in banner_lower):
            return mysql_match.group(1)

        # Redis – "+PONG" or "redis_version:7.0.5"
        if '+pong' in banner_lower:
            return 'Redis (PONG response)'
        redis_match = re.search(r'redis_version:(\S+)', banner)
        if redis_match:
            return f"Redis {redis_match.group(1)}"

        # Generic version pattern: "Name/1.2.3" or "Name 1.2.3"
        generic_match = re.search(r'([\w\-]+)[/\s](\d+\.\d+[\.\d]*\S*)', banner)
        if generic_match:
            return f"{generic_match.group(1)} {generic_match.group(2)}"

        # Return first non-empty line (truncated)
        first_line = banner.split('\n')[0].strip()
        return first_line[:120] if first_line else "Version Unknown"

    # ──────────────────────────────────────────────────────────────
    #  High-level detection for a single port
    # ──────────────────────────────────────────────────────────────
    def detect_service(self, target, port, timeout=3):
        """
        Detect service running on one port: name + version via banner.

        Args:
            target (str): Target IP
            port (int): Port number
            timeout (int): Banner grab timeout

        Returns:
            dict: {port, service, description, version, banner}
        """
        service_name, description = self.get_service_name(port)

        service_info = {
            'port': port,
            'service': service_name,
            'description': description,
            'version': 'Version Unknown',
            'banner': None,
        }

        # Try banner grabbing
        banner = self.grab_banner(target, port, timeout=timeout)
        if banner:
            service_info['banner'] = banner
            service_info['version'] = self.extract_version(banner)

            # Refine service name based on banner keywords
            bl = banner.lower()
            if 'ssh' in bl and service_name == 'Unknown':
                service_info['service'] = 'SSH'
            elif ('http' in bl or 'html' in bl) and service_name == 'Unknown':
                service_info['service'] = 'HTTP'
            elif 'ftp' in bl and service_name == 'Unknown':
                service_info['service'] = 'FTP'
            elif 'smtp' in bl and service_name == 'Unknown':
                service_info['service'] = 'SMTP'
            elif ('mysql' in bl or 'mariadb' in bl) and service_name == 'Unknown':
                service_info['service'] = 'MySQL'
            elif 'redis' in bl or '+pong' in bl:
                service_info['service'] = 'Redis'
            elif 'vnc' in bl:
                service_info['service'] = 'VNC'
            elif 'rdp' in bl or 'microsoft' in bl:
                service_info['service'] = 'RDP'
            elif 'ssl' in bl or 'tls' in bl:
                if service_name == 'Unknown':
                    service_info['service'] = 'SSL/TLS'

        return service_info

    # ──────────────────────────────────────────────────────────────
    #  Detect services for multiple ports (with threading)
    # ──────────────────────────────────────────────────────────────
    def detect_services(self, target, ports, timeout=3, threads=10, callback=None):
        """
        Detect services on multiple ports concurrently.

        Args:
            target (str): Target IP
            ports (list): List of open port numbers
            timeout (int): Banner grab timeout per port
            threads (int): Number of concurrent threads for detection
            callback (func): Optional callback(service_info_dict) per port

        Returns:
            list: List of service info dicts, sorted by port
        """
        print(f"\n{Fore.CYAN}[*] Detecting services on {len(ports)} port(s)...{Style.RESET_ALL}\n")

        services = []
        lock = __import__('threading').Lock()

        def _detect_one(port):
            info = self.detect_service(target, port, timeout=timeout)
            with lock:
                services.append(info)
            # Print live
            version_str = info['version'] if info['version'] != 'Version Unknown' else Fore.YELLOW + 'Version Unknown' + Style.RESET_ALL
            print(
                f"  {Fore.GREEN}Port {info['port']:<6}{Style.RESET_ALL} | "
                f"{Fore.WHITE}{info['service']:<20}{Style.RESET_ALL} | "
                f"{version_str}"
            )
            if callback:
                callback(info)
            return info

        num_workers = min(threads, len(ports))
        with ThreadPoolExecutor(max_workers=num_workers) as executor:
            futures = {executor.submit(_detect_one, p): p for p in ports}
            for f in as_completed(futures):
                pass  # results collected via the shared list

        # Sort by port number
        services.sort(key=lambda s: s['port'])
        return services