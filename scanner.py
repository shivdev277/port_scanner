#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║  Advanced Port Scanner — CLI Interface                           ║
║  Version 2.0                                                     ║
║                                                                  ║
║  Usage:                                                          ║
║    python scanner.py -t 192.168.1.1                              ║
║    python scanner.py -t 192.168.1.1 -p 1-1000 -s                ║
║    python scanner.py -t 10.0.0.1 -p 1-65535 -s -o results.json  ║
║    python scanner.py --gui                                       ║
║                                                                  ║
║  ⚠  WARNING: This tool is for EDUCATIONAL and AUTHORIZED         ║
║     TESTING ONLY. Unauthorized port scanning is ILLEGAL.         ║
╚══════════════════════════════════════════════════════════════════╝
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
    save_results_txt,
    resolve_hostname,
)

# Initialize colorama for Windows colour support
init(autoreset=True)


def print_banner():
    """Display the CLI banner."""
    banner = f"""
{Fore.CYAN}╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║         Advanced Port Scanner v2.0                        ║
║         TCP Scan  ·  Service Detection  ·  Banner Grab    ║
║                                                           ║
║  ⚠  For educational & authorized testing only             ║
╚═══════════════════════════════════════════════════════════╝{Style.RESET_ALL}
    """
    print(banner)


def main():
    """Main CLI entry point."""
    print_banner()

    parser = argparse.ArgumentParser(
        description='Advanced Port Scanner — Scan ports and detect services',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
{Fore.YELLOW}Examples:{Style.RESET_ALL}
  Scan all 65535 ports:
    python scanner.py -t 192.168.1.1

  Scan specific range with service detection:
    python scanner.py -t 10.0.0.1 -p 1-1000 -s

  Scan & save results:
    python scanner.py -t 10.0.0.1 -p 1-1000 -s -o scan.json

  Launch the GUI:
    python scanner.py --gui
        """
    )

    parser.add_argument('-t', '--target', help='Target IP address or hostname')
    parser.add_argument('-p', '--ports', default='1-65535',
                        help='Port spec (e.g., "80", "1-1000", "22,80,443") [default: 1-65535]')
    parser.add_argument('-s', '--service-detection', action='store_true',
                        help='Enable service & version detection on open ports')
    parser.add_argument('-o', '--output',
                        help='Save results to file (.json / .csv / .txt)')
    parser.add_argument('--timeout', type=float, default=1.0,
                        help='Socket timeout in seconds [default: 1.0]')
    parser.add_argument('--threads', type=int, default=500,
                        help='Number of concurrent threads [default: 500]')
    parser.add_argument('--gui', action='store_true',
                        help='Launch the graphical interface instead of CLI')

    args = parser.parse_args()

    # ── GUI mode ──
    if args.gui:
        from gui_scanner import main as gui_main
        gui_main()
        return

    # ── CLI mode requires a target ──
    if not args.target:
        parser.print_help()
        print(f"\n{Fore.RED}[-] Error: -t/--target is required in CLI mode.{Style.RESET_ALL}")
        sys.exit(1)

    # Resolve target
    target = args.target
    if not validate_ip(target):
        print(f"{Fore.YELLOW}[*] '{target}' is not an IP — resolving hostname...{Style.RESET_ALL}")
        resolved = resolve_hostname(target)
        if resolved:
            print(f"{Fore.GREEN}[+] Resolved → {resolved}{Style.RESET_ALL}")
            target = resolved
        else:
            print(f"{Fore.RED}[-] Could not resolve: {target}{Style.RESET_ALL}")
            sys.exit(1)

    # Parse ports
    ports = parse_ports(args.ports)
    if not ports:
        print(f"{Fore.RED}[-] No valid ports to scan.{Style.RESET_ALL}")
        sys.exit(1)

    print(f"{Fore.GREEN}[+] Target   : {target}{Style.RESET_ALL}")
    print(f"{Fore.GREEN}[+] Ports    : {len(ports)}{Style.RESET_ALL}")
    print(f"{Fore.GREEN}[+] Threads  : {args.threads}{Style.RESET_ALL}")
    print(f"{Fore.GREEN}[+] Timeout  : {args.timeout}s{Style.RESET_ALL}")

    try:
        # ── Phase 1: Port Scan ──
        scanner = PortScanner(
            target=target, ports=ports,
            timeout=args.timeout, threads=args.threads
        )
        scan_results = scanner.scan()

        # ── Phase 2: Service Detection ──
        services_results = None
        if args.service_detection and scan_results['open_ports']:
            detector = ServiceDetector()
            services_results = detector.detect_services(
                target, scan_results['open_ports'],
                timeout=3, threads=min(10, len(scan_results['open_ports']))
            )

        # ── Display formatted report ──
        print(format_results(scan_results, services_results))

        # ── Save results ──
        if args.output:
            fname = args.output
            if fname.endswith('.json'):
                save_results_json(scan_results, services_results, fname)
            elif fname.endswith('.csv'):
                save_results_csv(scan_results, services_results, fname)
            elif fname.endswith('.txt'):
                save_results_txt(scan_results, services_results, fname)
            else:
                save_results_json(scan_results, services_results, fname + '.json')

        print(f"\n{Fore.GREEN}[+] Scan completed successfully!{Style.RESET_ALL}")

    except KeyboardInterrupt:
        print(f"\n\n{Fore.YELLOW}[!] Scan interrupted by user.{Style.RESET_ALL}")
        sys.exit(0)
    except Exception as e:
        print(f"\n{Fore.RED}[-] Error: {e}{Style.RESET_ALL}")
        sys.exit(1)


if __name__ == '__main__':
    main()