#!/usr/bin/env python3
import argparse
import sys
import os
import ipaddress
import json

# Add the current directory to the system path to ensure the 'core' module imports correctly
current_dir = os.path.dirname(os.path.realpath(__file__))
sys.path.insert(0, current_dir)

from core.scanner import run_scan
from checks.runner import CheckRunner

def print_banner():    
    # Define ANSI color codes for a professional terminal appearance
    CYAN = "\033[96m"
    RED = "\033[91m"
    WHITE = "\033[97m"
    YELLOW = "\033[93m"
    RESET = "\033[0m"

    ascii_art = r"""
    _____ _    _ _____  ______ _____  _   _  ______     __      
   / ____| |  | |  __ \|  ____|  __ \| \ | |/ __ \ \    / /\      
  | (___ | |  | | |__) | |__  | |__) |  \| | |  | \ \  / /  \     
   \___ \| |  | |  ___/|  __| |  _  /| . ` | |  | |\ \/ / /\ \    
   ____) | |__| | |    | |____| | \ \| |\  | |__| | \  / ____ \   
  |_____/ \____/|_|    |______|_|  \_\_| \_|\____/   \/_/    \_\  
    """
    
    print(CYAN + ascii_art + RESET)
    print(f"    {RED}[+] {WHITE}Internal Vulnerability Scanner Core")

def get_ips_from_target(target_str):
    """
    Parses the user's target input. 
    Returns a list of IP addresses for both single IPs and subnets (CIDR).
    """
    try:
        # Check if the target is a subnet (e.g., 192.168.1.0/24)
        if '/' in target_str:
            network = ipaddress.ip_network(target_str, strict=False)
            return [str(ip) for ip in network.hosts()]
        # Handle a single IP address
        else:
            ip = ipaddress.ip_address(target_str)
            return [str(ip)]
    except ValueError:
        return None

def parse_ports(port_arg):
    """
    Translates the user's port input into a list of integers.
    Supports predefined lists, ranges, and comma-separated values.
    """
    # Predefined common port lists
    top_15 = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 3306, 3389, 8080]
    top_100 = [7, 9, 13, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 106, 110, 111, 113, 119, 135, 139, 143, 144, 179, 199, 389, 427, 443, 444, 445, 465, 513, 514, 515, 543, 544, 548, 554, 587, 631, 646, 873, 990, 993, 995, 1025, 1026, 1027, 1028, 1029, 1110, 1433, 1720, 1723, 1755, 1900, 2000, 2001, 2049, 2121, 2717, 3000, 3128, 3306, 3389, 3986, 4899, 5000, 5009, 5051, 5060, 5190, 5357, 5432, 5631, 5666, 5800, 5900, 6000, 6001, 6646, 7070, 8000, 8008, 8009, 8080, 8081, 8443, 8888, 9100, 9999, 10000, 32768, 49152, 49153, 49154, 49155, 49156, 49157]

    # Default to top 15 if no argument is provided
    if not port_arg:
        return top_15
        
    port_arg = port_arg.lower().strip()
    
    # Handle specific string commands
    if port_arg == 'all' or port_arg == '-':
        return list(range(1, 65536))
    elif port_arg == 'top100':
        return top_100
    # Handle port ranges (e.g., 1-1000)
    elif '-' in port_arg:
        try:
            start, end = port_arg.split('-')
            return list(range(int(start), int(end) + 1))
        except ValueError:
            print("\033[91m[!] Error: Invalid port range format. Use start-end (e.g., 1-1000).\033[0m")
            sys.exit(1)
    # Handle comma-separated ports (e.g., 22,80,443)
    else:
        try:
            return [int(p.strip()) for p in port_arg.split(',')]
        except ValueError:
            print("\033[91m[!] Error: Ports must be numbers separated by commas.\033[0m")
            sys.exit(1)

def parse_arguments():
    """
    Sets up the CLI arguments using argparse.
    Defines flags for targets, ports, speed, and specific security modules.
    """
    parser = argparse.ArgumentParser(
        description="SUPERNOVA Internal Vulnerability Scanner",
        usage="supernova -t <TARGET_IP_OR_CIDR> [options]"
    )
    
    parser.add_argument("-t", "--target", dest="target", required=True, 
                        help="Target IP or Subnet CIDR (e.g., 192.168.1.1 or 192.168.1.0/24)")
    
    parser.add_argument("-p", "--ports", dest="ports", 
                        help="Ports to scan: 'top100', 'all', '1-1000', or '22,80' (Default: top 15)")
    
    parser.add_argument("--speed", dest="speed", type=float, default=1.0, 
                        help="Timeout in seconds per port (default: 1.0).")

    parser.add_argument("-o", "--output", dest="output", default="report.json", 
                        help="Output JSON file name (default: report.json).")

    # Future security check flags
    parser.add_argument("--all", action="store_true", help="Run all security checks")
    parser.add_argument("--ftp", action="store_true", help="Run FTP checks only")
    parser.add_argument("--smb", action="store_true", help="Run SMB checks only")
    parser.add_argument("--http", action="store_true", help="Run HTTP/HTTPS checks only")

    return parser.parse_args()

def main():
    """
    The main entry point of the script. Orchestrates parsing, scanning, and saving results.
    """
    print_banner()
    
    # Show a helpful tip if the user runs the tool without arguments
    if len(sys.argv) == 1:
        print("\033[93m[!] Missing required arguments.\033[0m")
        print("\033[97m[*] Tip: Type \033[96msupernova -h\033[0m \033[97mto see the help menu.\033[0m\n")
        sys.exit(1)    
        
    args = parse_arguments()
    
    # Validate and process the target IP/Subnet
    target_ips = get_ips_from_target(args.target)
    if not target_ips:
        print(f"\033[91m[!] Error: Invalid Target format '{args.target}'. Please use a valid IP or CIDR.\033[0m")
        sys.exit(1)
        
    # Process the requested ports
    target_ports = parse_ports(args.ports)
    
    print(f"\033[94m[*] Preparing to scan {len(target_ports)} ports...\033[0m")

    # Determine which security checks to run based on CLI flags
    run_checks = args.all or args.ftp or args.smb or args.http

    try:
        # Execute the core scanning engine
        scan_results = run_scan(target_ips=target_ips, scope_name=args.target, ports_to_scan=target_ports, timeout_sec=args.speed)
        
        # Step 4 (Optional): Run security checks if any check flags were provided
        if run_checks:
            print(f"\n\033[96m[*] Running Security Checks...\033[0m")
            runner = CheckRunner()
            
            for ip in target_ips:
                # Only run checks on hosts that are UP
                host_data = scan_results.get("hosts", {}).get(ip, {})
                if host_data.get("status") != "up":
                    continue
                
                open_ports = [p["port"] for p in host_data.get("ports", [])]
                check_results = []
                
                # Run FTP checks
                if args.all or args.ftp:
                    from checks.network_checks import check_ftp
                    ftp_port = 21 if 21 in open_ports else None
                    if ftp_port:
                        print(f"  [{ip}] Checking FTP (port {ftp_port})...")
                        check_results.append(check_ftp(ip, ftp_port))
                    else:
                        print(f"  [{ip}] FTP port 21 not open, skipping FTP check.")
                
                # Run SMB checks
                if args.all or args.smb:
                    from checks.network_checks import check_smb
                    smb_port = 445 if 445 in open_ports else None
                    if smb_port:
                        print(f"  [{ip}] Checking SMB (port {smb_port})...")
                        check_results.append(check_smb(ip, smb_port))
                    else:
                        print(f"  [{ip}] SMB port 445 not open, skipping SMB check.")
                
                # Run HTTP checks
                if args.all or args.http:
                    from checks.web_checks import check_http, check_security_headers
                    http_port = 80 if 80 in open_ports else (8080 if 8080 in open_ports else None)
                    if http_port:
                        print(f"  [{ip}] Checking HTTP (port {http_port})...")
                        check_results.append(check_http(ip, http_port))
                        print(f"  [{ip}] Checking Security Headers (port {http_port})...")
                        check_results.append(check_security_headers(ip, http_port))
                    else:
                        print(f"  [{ip}] HTTP port 80/8080 not open, skipping HTTP checks.")
                
                # Add check results to the scan report
                if check_results:
                    scan_results["hosts"][ip]["security_checks"] = check_results
                    
                    # Print summary
                    vuln_count = sum(1 for c in check_results if c.get("vulnerable"))
                    print(f"\n  \033[93m[!] {ip}: {vuln_count} vulnerability/misconfig found out of {len(check_results)} checks.\033[0m")
                    for c in check_results:
                        status_color = "\033[91m" if c.get("vulnerable") else "\033[92m"
                        vuln_label = "VULNERABLE" if c.get("vulnerable") else "OK"
                        print(f"    {status_color}[{vuln_label}]\033[0m {c.get('service', 'N/A')}: {c.get('description', 'N/A')}")
        
        # Save the results to the specified JSON file for reporting
        with open(args.output, 'w') as json_file:
            json.dump(scan_results, json_file, indent=4)
            
        print(f"\n\033[92m[+] Scan report successfully saved to: {args.output}\033[0m")

    # Handle Ctrl+C gracefully without throwing messy errors
    except KeyboardInterrupt:
        print(f"\n\033[93m[!] Scan interrupted by user. Exiting...\033[0m")
        sys.exit(0)

if __name__ == "__main__":
    main()
