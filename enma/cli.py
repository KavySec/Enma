#!/usr/bin/env python3
# made this bc i kept forgetting what changed between my recon scans lol

import argparse
import sys
import json
from datetime import datetime

from enma.scanner import Scanner
from enma.differ import Differ
from enma.reporter import Reporter


def banner():
    print(r"""
 _____ _   _ __  __    _    
| ____| \ | |  \/  |  / \   
|  _| |  \| | |\/| | / _ \  
| |___| |\  | |  | |/ ___ \ 
|_____|_| \_|_|  |_/_/   \_\
   [ Red Team ReconDiff v1.0 ]
    """)


def scan_mode(args):
    scanner = Scanner(args.target)
    
    if args.ports:
        ports = args.ports
    elif args.fast:
        ports = "1-1000"
    else:
        ports = "1-65535"
    
    print(f"\n[*] Port range: {ports}")
    if ports == "1-65535":
        print("[*] Scanning all ports... this may take 10-20 minutes")
        print("[*] Please wait, don't close the terminal\n")
    
    scanner.run_all(ports)
    
    if not args.output:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_target = args.target.replace("/", "_").replace("\\", "_")
        args.output = f"scan_{safe_target}_{timestamp}.json"
    
    try:
        scanner.save(args.output)
    except OSError as e:
        print(f"[!] Could not save results: {e}")
        sys.exit(1)
    print(f"\n[+] Done! Scan saved to {args.output}")
    print(f"    Run: enma diff {args.output} <newer_scan.json> to compare")


def diff_mode(args):
    try:
        with open(args.scan1, "r") as f:
            scan1 = json.load(f)
        with open(args.scan2, "r") as f:
            scan2 = json.load(f)
    except FileNotFoundError as e:
        print(f"[!] Error: {e}")
        sys.exit(1)
    except json.JSONDecodeError:
        print("[!] Error: Invalid JSON file")
        sys.exit(1)
    
    differ = Differ(scan1, scan2)
    diff = differ.compare_all()
    
    reporter = Reporter(diff, scan1, scan2)
    
    if args.json:
        print(reporter.json_report())
    else:
        print(reporter.text_report())
    
    if args.output:
        with open(args.output, "w") as f:
            if args.json:
                f.write(reporter.json_report())
            else:
                f.write(reporter.text_report())
        print(f"\n[+] Report saved to {args.output}")


def main():
    banner()
    
    parser = argparse.ArgumentParser(
        description="ReconDiff - Compare reconnaissance results over time",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  enma scan example.com
  enma scan example.com --fast
  enma scan example.com -p 80,443,8080
  enma scan example.com -o myscan.json
  enma diff scan1.json scan2.json
  enma diff scan1.json scan2.json --json -o report.json
        """
    )
    
    subparsers = parser.add_subparsers(dest="mode", help="Mode to run")
    
    scan_parser = subparsers.add_parser("scan", help="Run a new recon scan")
    scan_parser.add_argument("target", help="Target domain or IP")
    scan_parser.add_argument("-p", "--ports", help="Port range (default: all ports)")
    scan_parser.add_argument("-o", "--output", help="Output filename")
    scan_parser.add_argument("--fast", action="store_true", help="Scan only top 1000 ports (faster)")
    
    diff_parser = subparsers.add_parser("diff", help="Compare two scans")
    diff_parser.add_argument("scan1", help="First scan (older)")
    diff_parser.add_argument("scan2", help="Second scan (newer)")
    diff_parser.add_argument("-o", "--output", help="Save report to file")
    diff_parser.add_argument("--json", action="store_true", help="Output as JSON")
    
    args = parser.parse_args()
    
    if not args.mode:
        parser.print_help()
        sys.exit(0)
    
    if args.mode == "scan":
        scan_mode(args)
    elif args.mode == "diff":
        diff_mode(args)


if __name__ == "__main__":
    main()
