"""
Utility Functions
Helper functions for the port scanner
"""

import socket
import json
import csv
import os
from datetime import datetime


def validate_ip(ip):
    """
    Validate IP address format
    
    Args:
        ip (str): IP address to validate
        
    Returns:
        bool: True if valid, False otherwise
    """
    try:
        socket.inet_aton(ip)
        return True
    except socket.error:
        return False


def parse_ports(port_string):
    """
    Parse port string into list of port numbers
    Supports formats: "80", "80,443,8080", "1-100", "1-100,443,8080-8090"
    
    Args:
        port_string (str): Port specification string
        
    Returns:
        list: List of port numbers
    """
    ports = set()
    
    # Split by comma
    parts = port_string.split(',')
    
    for part in parts:
        part = part.strip()
        
        # Check if it's a range
        if '-' in part:
            try:
                start, end = part.split('-')
                start, end = int(start), int(end)
                
                if start > end:
                    start, end = end, start
                
                if start < 1 or end > 65535:
                    raise ValueError("Ports must be between 1 and 65535")
                
                ports.update(range(start, end + 1))
            except ValueError as e:
                print(f"Error parsing port range '{part}': {e}")
        else:
            # Single port
            try:
                port = int(part)
                if 1 <= port <= 65535:
                    ports.add(port)
                else:
                    print(f"Invalid port number: {port}")
            except ValueError:
                print(f"Invalid port specification: {part}")
    
    return sorted(list(ports))


def format_results(scan_results, services_results=None):
    """
    Format scan results for display
    
    Args:
        scan_results (dict): Results from port scan
        services_results (list): Service detection results
        
    Returns:
        str: Formatted results
    """
    output = []
    output.append("\n" + "="*70)
    output.append("SCAN RESULTS")
    output.append("="*70)
    output.append(f"Target: {scan_results['target']}")
    output.append(f"Start Time: {scan_results['start_time']}")
    output.append(f"End Time: {scan_results['end_time']}")
    output.append(f"Duration: {scan_results['duration']:.2f} seconds")
    output.append(f"Total Ports Scanned: {scan_results['total_ports_scanned']}")
    output.append(f"Open Ports Found: {len(scan_results['open_ports'])}")
    output.append("="*70)
    
    if scan_results['open_ports']:
        output.append("\nOPEN PORTS:")
        output.append("-"*70)
        
        if services_results:
            for service in services_results:
                output.append(f"  Port {service['port']:<6} - {service['service']:<20}")
                if service['description']:
                    output.append(f"    {service['description']}")
                if service['banner']:
                    banner = service['banner'][:80] + '...' if len(service['banner']) > 80 else service['banner']
                    output.append(f"    Banner: {banner}")
                output.append("")
        else:
            for port in scan_results['open_ports']:
                output.append(f"  {port}")
    else:
        output.append("\nNo open ports found.")
    
    output.append("="*70 + "\n")
    
    return "\n".join(output)


def save_results_json(scan_results, services_results, filename):
    """
    Save results to JSON file
    
    Args:
        scan_results (dict): Scan results
        services_results (list): Service detection results
        filename (str): Output filename
    """
    output_data = {
        'scan_info': scan_results,
        'services': services_results if services_results else []
    }
    
    # Create results directory if it doesn't exist
    os.makedirs('results', exist_ok=True)
    
    filepath = os.path.join('results', filename)
    
    with open(filepath, 'w') as f:
        json.dump(output_data, f, indent=4)
    
    print(f"\n[+] Results saved to: {filepath}")


def save_results_csv(scan_results, services_results, filename):
    """
    Save results to CSV file
    
    Args:
        scan_results (dict): Scan results
        services_results (list): Service detection results
        filename (str): Output filename
    """
    os.makedirs('results', exist_ok=True)
    filepath = os.path.join('results', filename)
    
    with open(filepath, 'w', newline='') as f:
        if services_results:
            fieldnames = ['port', 'service', 'description', 'banner']
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            
            for service in services_results:
                writer.writerow({
                    'port': service['port'],
                    'service': service['service'],
                    'description': service['description'],
                    'banner': service['banner'] if service['banner'] else ''
                })
        else:
            writer = csv.writer(f)
            writer.writerow(['Port'])
            for port in scan_results['open_ports']:
                writer.writerow([port])
    
    print(f"[+] Results saved to: {filepath}")


def get_local_ip():
    """
    Get local IP address
    
    Returns:
        str: Local IP address
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except:
        return "127.0.0.1"


def resolve_hostname(hostname):
    """
    Resolve hostname to IP address
    
    Args:
        hostname (str): Hostname to resolve
        
    Returns:
        str: IP address or None
    """
    try:
        return socket.gethostbyname(hostname)
    except socket.gaierror:
        return None