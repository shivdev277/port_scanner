#!/usr/bin/env python3
"""
Network Port Scanner
A Python-based port scanning tool similar to Nmap

Usage:
    python3 scanner.py -t 192.168.1.1 -p 1-100
    python3 scanner.py -t example.com -p 80,443,8080 -s
    python3 scanner.py -t 10.0.0.1 -p 1-1000 -s -o results.json
"""

import argparse
import sys
from colorama import Fore, Style, init
from core.port_scanner import PortScanner
from core.service_detector import ServiceDetector
from core.utils import (
    validate_ip, 
    parse_ports, 
    format_results, 
    save_results_json,
    save_results_csv,
    resolve_hostname
)

# Initialize colorama
init(autoreset=True)


def print_banner():
    """Display tool banner"""
    banner = f"""
{Fore.CYAN}╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║           Network Port Scanner v1.0                       ║
║           Scan ports and detect services                  ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝{Style.RESET_ALL}
    """
    print(banner)


def main():
    """Main function"""
    print_banner()
    
    # Argument parser
    parser = argparse.ArgumentParser(
        description='Network Port Scanner - Scan ports and detect services',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Scan common ports:
    python3 scanner.py -t 192.168.1.1 -p 1-1000
  
  Scan specific ports with service detection:
    python3 scanner.py -t example.com -p 22,80,443,8080 -s
  
  Scan and save results:
    python3 scanner.py -t 10.0.0.1 -p 1-100 -s -o scan_results.json
  
  Fast scan of top ports:
    python3 scanner.py -t 192.168.1.1 -p 21,22,23,25,53,80,110,143,443,3389
        """
    )
    
    parser.add_argument(
        '-t', '--target',
        required=True,
        help='Target IP address or hostname'
    )
    
    parser.add_argument(
        '-p', '--ports',
        default='1-1000',
        help='Port specification (e.g., "80", "1-100", "22,80,443,8000-9000")'
    )
    
    parser.add_argument(
        '-s', '--service-detection',
        action='store_true',
        help='Enable service detection on open ports'
    )
    
    parser.add_argument(
        '-o', '--output',
        help='Save results to file (supports .json and .csv)'
    )
    
    parser.add_argument(
        '--timeout',
        type=float,
        default=1.0,
        help='Socket timeout in seconds (default: 1.0)'
    )
    
    parser.add_argument(
        '--threads',
        type=int,
        default=100,
        help='Number of concurrent threads (default: 100)'
    )
    
    args = parser.parse_args()
    
    # Resolve target
    target = args.target
    if not validate_ip(target):
        print(f"{Fore.YELLOW}[*] '{target}' is not a valid IP, attempting to resolve hostname...{Style.RESET_ALL}")
        resolved_ip = resolve_hostname(target)
        if resolved_ip:
            print(f"{Fore.GREEN}[+] Resolved {target} to {resolved_ip}{Style.RESET_ALL}")
            target = resolved_ip
        else:
            print(f"{Fore.RED}[-] Could not resolve hostname: {target}{Style.RESET_ALL}")
            sys.exit(1)
    
    # Parse ports
    ports = parse_ports(args.ports)
    if not ports:
        print(f"{Fore.RED}[-] No valid ports to scan{Style.RESET_ALL}")
        sys.exit(1)
    
    print(f"{Fore.GREEN}[+] Target: {target}{Style.RESET_ALL}")
    print(f"{Fore.GREEN}[+] Ports to scan: {len(ports)}{Style.RESET_ALL}")
    print(f"{Fore.GREEN}[+] Timeout: {args.timeout}s{Style.RESET_ALL}")
    print(f"{Fore.GREEN}[+] Threads: {args.threads}{Style.RESET_ALL}")
    
    try:
        # Initialize scanner
        scanner = PortScanner(
            target=target,
            ports=ports,
            timeout=args.timeout,
            threads=args.threads
        )
        
        # Perform scan
        scan_results = scanner.scan()
        
        # Service detection
        services_results = None
        if args.service_detection and scan_results['open_ports']:
            detector = ServiceDetector()
            services_results = detector.detect_services(target, scan_results['open_ports'])
        
        # Display formatted results
        print(format_results(scan_results, services_results))
        
        # Save results if output specified
        if args.output:
            if args.output.endswith('.json'):
                save_results_json(scan_results, services_results, args.output)
            elif args.output.endswith('.csv'):
                save_results_csv(scan_results, services_results, args.output)
            else:
                # Default to JSON
                output_file = args.output + '.json'
                save_results_json(scan_results, services_results, output_file)
        
        print(f"\n{Fore.GREEN}[+] Scan completed successfully!{Style.RESET_ALL}")
        
    except KeyboardInterrupt:
        print(f"\n\n{Fore.YELLOW}[!] Scan interrupted by user{Style.RESET_ALL}")
        sys.exit(0)
    except Exception as e:
        print(f"\n{Fore.RED}[-] Error: {str(e)}{Style.RESET_ALL}")
        sys.exit(1)


if __name__ == '__main__':
    main()