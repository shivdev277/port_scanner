"""
Service Detection Module
Identifies services running on open ports
"""

import socket
import json
import os
from colorama import Fore, Style


class ServiceDetector:
    """
    Detects services running on open ports
    """
    
    def __init__(self):
        """
        Initialize service detector and load service database
        """
        self.services_db = self._load_services_db()
    
    def _load_services_db(self):
        """
        Load common port-service mappings from JSON file
        
        Returns:
            dict: Port to service mappings
        """
        db_path = os.path.join(os.path.dirname(__file__), '..', 'data', 'services.json')
        
        try:
            with open(db_path, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            # Return default common services if file not found
            return self._get_default_services()
    
    def _get_default_services(self):
        """
        Return default common port-service mappings
        
        Returns:
            dict: Common port to service mappings
        """
        return {
            "21": {"service": "FTP", "description": "File Transfer Protocol"},
            "22": {"service": "SSH", "description": "Secure Shell"},
            "23": {"service": "Telnet", "description": "Telnet"},
            "25": {"service": "SMTP", "description": "Simple Mail Transfer Protocol"},
            "53": {"service": "DNS", "description": "Domain Name System"},
            "80": {"service": "HTTP", "description": "Hypertext Transfer Protocol"},
            "110": {"service": "POP3", "description": "Post Office Protocol v3"},
            "143": {"service": "IMAP", "description": "Internet Message Access Protocol"},
            "443": {"service": "HTTPS", "description": "HTTP Secure"},
            "3306": {"service": "MySQL", "description": "MySQL Database"},
            "3389": {"service": "RDP", "description": "Remote Desktop Protocol"},
            "5432": {"service": "PostgreSQL", "description": "PostgreSQL Database"},
            "6379": {"service": "Redis", "description": "Redis Database"},
            "8080": {"service": "HTTP-Proxy", "description": "HTTP Alternate"},
            "8443": {"service": "HTTPS-Alt", "description": "HTTPS Alternate"},
            "27017": {"service": "MongoDB", "description": "MongoDB Database"}
        }
    
    def grab_banner(self, target, port, timeout=2):
        """
        Attempt to grab banner from a service
        
        Args:
            target (str): Target IP address
            port (int): Port number
            timeout (int): Connection timeout
            
        Returns:
            str: Banner text or None
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((target, port))
            
            # Send a generic request (works for many protocols)
            try:
                sock.send(b'HEAD / HTTP/1.0\r\n\r\n')
            except:
                pass
            
            # Try to receive banner
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            sock.close()
            
            return banner if banner else None
            
        except Exception as e:
            return None
    
    def detect_service(self, target, port):
        """
        Detect service running on a port
        
        Args:
            target (str): Target IP address
            port (int): Port number
            
        Returns:
            dict: Service information
        """
        port_str = str(port)
        service_info = {
            'port': port,
            'service': 'Unknown',
            'description': '',
            'banner': None
        }
        
        # Check database for known service
        if port_str in self.services_db:
            service_info['service'] = self.services_db[port_str]['service']
            service_info['description'] = self.services_db[port_str]['description']
        
        # Try to grab banner
        banner = self.grab_banner(target, port)
        if banner:
            service_info['banner'] = banner
            
            # Try to refine service detection based on banner
            banner_lower = banner.lower()
            if 'ssh' in banner_lower:
                service_info['service'] = 'SSH'
            elif 'http' in banner_lower or 'html' in banner_lower:
                service_info['service'] = 'HTTP'
            elif 'ftp' in banner_lower:
                service_info['service'] = 'FTP'
            elif 'smtp' in banner_lower:
                service_info['service'] = 'SMTP'
            elif 'mysql' in banner_lower:
                service_info['service'] = 'MySQL'
        
        return service_info
    
    def detect_services(self, target, ports):
        """
        Detect services for multiple ports
        
        Args:
            target (str): Target IP address
            ports (list): List of port numbers
            
        Returns:
            list: List of service information dictionaries
        """
        print(f"\n{Fore.CYAN}[*] Detecting services...{Style.RESET_ALL}\n")
        
        services = []
        for port in ports:
            service_info = self.detect_service(target, port)
            services.append(service_info)
            
            # Display service info
            print(f"{Fore.GREEN}Port {port}:\t{service_info['service']}{Style.RESET_ALL}")
            if service_info['description']:
                print(f"  {Fore.YELLOW}└─ {service_info['description']}{Style.RESET_ALL}")
            if service_info['banner']:
                banner_preview = service_info['banner'][:100] + '...' if len(service_info['banner']) > 100 else service_info['banner']
                print(f"  {Fore.CYAN}└─ Banner: {banner_preview}{Style.RESET_ALL}")
        
        return services