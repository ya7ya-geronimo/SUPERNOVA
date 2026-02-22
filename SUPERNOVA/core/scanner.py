import datetime
import getpass
from core.discovery import is_host_up
from core.portscan import scan_multiple_ports
from core.banner_grabber import grab_banner
from core.service_detection import detect_service_and_version

def run_scan(target_ips, scope_name, ports_to_scan, timeout_sec=1.0):
    """
    The main orchestration engine of the scanner.
    Executes a structured 3-step process (Discovery, Scanning, Fingerprinting) for each target
    and compiles the results into a structured JSON dictionary.
    """
    
    # Capture the exact time and the system user running the scan for reporting metadata
    scan_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    current_user = getpass.getuser()
    
    # Initialize the base structure for the JSON report
    scan_results = {
        "metadata": {
            "team": "SUPERNOVA",
            "scope": scope_name,
            "time": scan_time,
            "user": current_user
        },
        "hosts": {}
    }
    
    # Print the scan metadata header to the terminal
    print("="*65)
    print(f"[*] Team           : SUPERNOVA")
    print(f"[*] Scope (Target) : {scope_name} (Total Hosts: {len(target_ips)})")
    print(f"[*] Time of Scan   : {scan_time}")
    print(f"[*] Scan run by    : {current_user}")
    print("="*65)
    
    # Iterate through all IP addresses provided in the target scope
    for ip in target_ips:
        print(f"\n{'='*20} TARGET: {ip} {'='*20}")
        
        # Initialize the default status for the current IP in the JSON report
        scan_results["hosts"][ip] = {"status": "down", "ports": []}
        
        # Step 1: Host Discovery (ICMP Ping Check)
        print(f"[{ip}] Step 1: Checking if host is UP...")
        if not is_host_up(ip, timeout_sec=timeout_sec):
            print(f"[-] Host {ip} is DOWN. Skipping to next host...")
            continue
            
        print(f"[+] Host {ip} is UP!")
        scan_results["hosts"][ip]["status"] = "up"
        
        # Step 2: Port Scanning (Multi-threaded execution)
        print(f"[{ip}] Step 2: Scanning ports...")
        open_ports = scan_multiple_ports(ip, ports_to_scan, timeout_sec=timeout_sec)
        
        # If no open ports are found, move on to the next target
        if not open_ports:
            print(f"[-] No open ports found on {ip}.")
            continue
            
        print(f"[+] Found {len(open_ports)} open ports: {open_ports}")
        
        # Step 3: Service Enumeration (Banner Grabbing & Service Detection)
        print(f"[{ip}] Step 3: Detecting Services and Versions...")
        print("-" * 55)
        print(f"{'PORT':<8} | {'SERVICE':<10} | {'VERSION'}")
        print("-" * 55)
        
        # Iterate through every open port found to identify the service running behind it
        for port in open_ports:
            banner = grab_banner(ip, port, timeout_sec=timeout_sec)
            
            # Map the banner to a known service and version using the detection module
            service, version = detect_service_and_version(banner, port, target_ip=ip)
            
            # Append the detected details to the JSON report dictionary
            scan_results["hosts"][ip]["ports"].append({
                "port": port,
                "service": service,
                "version": version
            })
            
            # Print the formatted result row to the terminal
            print(f"{port:<8} | {service:<10} | {version}")
            
        print("-" * 55)
        
    print("\n[+] All tasks completed for the given scope!")
    
    # Return the fully populated dictionary to be saved as a JSON file by main.py
    return scan_results
