"""
╔══════════════════════════════════════════════════════════════════╗
║  Utility Functions for Advanced Port Scanner                     ║
║  IP validation, port parsing, result formatting, file I/O        ║
║                                                                  ║
║  WARNING: This tool is for EDUCATIONAL and AUTHORIZED testing    ║
║  only. Unauthorized scanning of networks is ILLEGAL.             ║
╚══════════════════════════════════════════════════════════════════╝
"""

import socket
import json
import csv
import os
from datetime import datetime


# ══════════════════════════════════════════════════════════════════
#  Validation helpers
# ══════════════════════════════════════════════════════════════════
def validate_ip(ip):
    """
    Validate an IPv4 address string.

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


def resolve_hostname(hostname):
    """
    Resolve a hostname to its IPv4 address.

    Args:
        hostname (str): Hostname to resolve

    Returns:
        str or None: Resolved IP address, or None on failure
    """
    try:
        return socket.gethostbyname(hostname)
    except socket.gaierror:
        return None


# ══════════════════════════════════════════════════════════════════
#  Port parsing
# ══════════════════════════════════════════════════════════════════
def parse_ports(port_string):
    """
    Parse a port specification string into a sorted list of integers.

    Supported formats:
        "80"              → [80]
        "80,443,8080"     → [80, 443, 8080]
        "1-100"           → [1, 2, ..., 100]
        "1-100,443,8000-8090"

    Args:
        port_string (str): Port specification string

    Returns:
        list[int]: Sorted list of unique port numbers
    """
    ports = set()
    parts = port_string.split(',')

    for part in parts:
        part = part.strip()
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
            try:
                port = int(part)
                if 1 <= port <= 65535:
                    ports.add(port)
                else:
                    print(f"Invalid port number: {port}")
            except ValueError:
                print(f"Invalid port specification: {part}")

    return sorted(ports)


# ══════════════════════════════════════════════════════════════════
#  Result formatting (terminal / text)
# ══════════════════════════════════════════════════════════════════
def format_results(scan_results, services_results=None):
    """
    Format scan results into a clean, Nmap-style report string.

    Args:
        scan_results (dict): Results from PortScanner.scan()
        services_results (list): List of dicts from ServiceDetector

    Returns:
        str: Formatted multi-line report
    """
    output = []
    output.append("\n" + "═" * 70)
    output.append("  SCAN RESULTS")
    output.append("═" * 70)
    output.append(f"  Target           : {scan_results['target']}")
    output.append(f"  Start Time       : {scan_results['start_time']}")
    output.append(f"  End Time         : {scan_results['end_time']}")
    output.append(f"  Duration         : {scan_results['duration']:.2f} seconds")
    output.append(f"  Ports Scanned    : {scan_results['total_ports_scanned']}")
    output.append(f"  Open Ports Found : {len(scan_results['open_ports'])}")
    output.append("═" * 70)

    if scan_results['open_ports']:
        output.append("")
        output.append("  PORT       SERVICE              VERSION")
        output.append("  " + "─" * 66)

        if services_results:
            for svc in services_results:
                port_str = str(svc['port'])
                service_str = svc.get('service', 'Unknown')
                version_str = svc.get('version', 'Version Unknown')
                output.append(
                    f"  {port_str:<10} {service_str:<20} {version_str}"
                )
                if svc.get('banner'):
                    banner_preview = svc['banner'][:80]
                    if len(svc['banner']) > 80:
                        banner_preview += '...'
                    output.append(f"             └─ Banner: {banner_preview}")
        else:
            # No service detection – show service names from DB
            try:
                from core.service_detector import ServiceDetector
                detector = ServiceDetector()
            except Exception:
                detector = None

            for port in scan_results['open_ports']:
                if detector:
                    sname, desc = detector.get_service_name(port)
                else:
                    sname, desc = 'Unknown', ''
                output.append(
                    f"  {str(port):<10} {sname:<20} {'─'}"
                )
    else:
        output.append("\n  No open ports found.")

    output.append("")
    output.append("═" * 70 + "\n")
    return "\n".join(output)


def format_results_for_gui(scan_results, services_results=None):
    """
    Format results specifically for the GUI output pane. Returns
    a list of (line_text, tag) tuples where tag controls colour.

    Tags: 'header', 'info', 'port_open', 'version', 'banner', 'divider'
    """
    lines = []
    lines.append(("═" * 62, 'divider'))
    lines.append(("  SCAN RESULTS", 'header'))
    lines.append(("═" * 62, 'divider'))
    lines.append((f"  Target           : {scan_results['target']}", 'info'))
    lines.append((f"  Duration         : {scan_results['duration']:.2f}s", 'info'))
    lines.append((f"  Ports Scanned    : {scan_results['total_ports_scanned']}", 'info'))
    lines.append((f"  Open Ports       : {len(scan_results['open_ports'])}", 'info'))
    lines.append(("═" * 62, 'divider'))

    if services_results:
        lines.append(("", 'info'))
        lines.append(("  PORT       SERVICE              VERSION", 'header'))
        lines.append(("  " + "─" * 58, 'divider'))
        for svc in services_results:
            port_str = str(svc['port'])
            service_str = svc.get('service', 'Unknown')
            version_str = svc.get('version', 'Version Unknown')
            lines.append(
                (f"  {port_str:<10} {service_str:<20} {version_str}", 'port_open')
            )
            if svc.get('banner'):
                banner_preview = svc['banner'][:70]
                if len(svc['banner']) > 70:
                    banner_preview += '...'
                lines.append((f"             └─ {banner_preview}", 'banner'))
    elif scan_results['open_ports']:
        lines.append(("", 'info'))
        for port in scan_results['open_ports']:
            lines.append((f"  Port {port} is OPEN", 'port_open'))
    else:
        lines.append(("\n  No open ports found.", 'info'))

    lines.append(("", 'info'))
    lines.append(("═" * 62, 'divider'))
    return lines


# ══════════════════════════════════════════════════════════════════
#  File output: JSON, CSV, TXT
# ══════════════════════════════════════════════════════════════════
def save_results_json(scan_results, services_results, filename):
    """Save scan results to a JSON file in the results/ directory."""
    output_data = {
        'scan_info': scan_results,
        'services': services_results if services_results else []
    }
    os.makedirs('results', exist_ok=True)
    filepath = os.path.join('results', filename)
    with open(filepath, 'w') as f:
        json.dump(output_data, f, indent=4)
    print(f"\n[+] Results saved to: {filepath}")
    return filepath


def save_results_csv(scan_results, services_results, filename):
    """Save scan results to a CSV file in the results/ directory."""
    os.makedirs('results', exist_ok=True)
    filepath = os.path.join('results', filename)

    with open(filepath, 'w', newline='') as f:
        if services_results:
            fieldnames = ['port', 'service', 'description', 'version', 'banner']
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for svc in services_results:
                writer.writerow({
                    'port': svc['port'],
                    'service': svc['service'],
                    'description': svc.get('description', ''),
                    'version': svc.get('version', ''),
                    'banner': svc.get('banner', '') or '',
                })
        else:
            writer = csv.writer(f)
            writer.writerow(['Port'])
            for port in scan_results['open_ports']:
                writer.writerow([port])

    print(f"[+] Results saved to: {filepath}")
    return filepath


def save_results_txt(scan_results, services_results, filename):
    """
    Save scan results to a plain-text (.txt) file.

    Args:
        scan_results (dict): Scan results
        services_results (list): Service detection results
        filename (str): Output filename

    Returns:
        str: Path to the saved file
    """
    os.makedirs('results', exist_ok=True)
    filepath = os.path.join('results', filename)

    report = format_results(scan_results, services_results)
    with open(filepath, 'w') as f:
        f.write(report)

    print(f"[+] Results saved to: {filepath}")
    return filepath


# ══════════════════════════════════════════════════════════════════
#  Network helpers
# ══════════════════════════════════════════════════════════════════
def get_local_ip():
    """
    Detect this machine's local IP address.

    Returns:
        str: Local IP address (falls back to 127.0.0.1)
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except Exception:
        return "127.0.0.1"