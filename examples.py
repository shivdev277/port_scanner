#!/usr/bin/env python3
"""
Example/Test Script
Demonstrates how to use the port scanner programmatically
"""

from core.port_scanner import PortScanner
from core.service_detector import ServiceDetector
from core.utils import validate_ip, parse_ports


def example_basic_scan():
    """Example: Basic port scan"""
    print("\n=== Example 1: Basic Port Scan ===\n")
    
    target = "127.0.0.1"  # localhost
    ports = parse_ports("1-100")  # Scan first 100 ports
    
    scanner = PortScanner(target=target, ports=ports, timeout=0.5, threads=50)
    results = scanner.scan()
    
    print(f"Found {len(results['open_ports'])} open ports")
    print(f"Open ports: {results['open_ports']}")


def example_specific_ports():
    """Example: Scan specific ports"""
    print("\n=== Example 2: Scan Specific Ports ===\n")
    
    target = "127.0.0.1"
    ports = parse_ports("22,80,443,3306,5432,8080")
    
    scanner = PortScanner(target=target, ports=ports)
    results = scanner.scan()


def example_with_service_detection():
    """Example: Scan with service detection"""
    print("\n=== Example 3: Scan with Service Detection ===\n")
    
    target = "127.0.0.1"
    ports = parse_ports("1-1000")
    
    # Port scan
    scanner = PortScanner(target=target, ports=ports, timeout=0.5)
    scan_results = scanner.scan()
    
    # Service detection
    if scan_results['open_ports']:
        detector = ServiceDetector()
        services = detector.detect_services(target, scan_results['open_ports'])
        
        print("\nServices detected:")
        for service in services:
            print(f"  Port {service['port']}: {service['service']}")


def example_custom_usage():
    """Example: Custom programmatic usage"""
    print("\n=== Example 4: Custom Usage ===\n")
    
    # Validate IP
    target = "192.168.1.1"
    if not validate_ip(target):
        print(f"{target} is not a valid IP")
        return
    
    # Parse port range
    ports = parse_ports("80,443,8080-8090")
    print(f"Scanning {len(ports)} ports: {ports}")
    
    # Create scanner with custom settings
    scanner = PortScanner(
        target=target,
        ports=ports,
        timeout=2.0,  # Longer timeout
        threads=20    # Fewer threads
    )
    
    # Run scan
    results = scanner.scan()
    
    # Process results
    if results['open_ports']:
        print("\nDetailed results:")
        print(f"  Target: {results['target']}")
        print(f"  Duration: {results['duration']:.2f}s")
        print(f"  Open ports: {results['open_ports']}")


if __name__ == '__main__':
    print("Port Scanner - Example Usage")
    print("=" * 60)
    
    # Run examples
    example_basic_scan()
    
    # Uncomment to run other examples:
    # example_specific_ports()
    # example_with_service_detection()
    # example_custom_usage()
    
    print("\n" + "=" * 60)
    print("Examples completed!")