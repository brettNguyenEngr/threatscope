import nmap
import json
import re
import socket
import ipaddress

def tool_ping_sweep(target_subnet: str) -> str:
    """
    Tool 1: Discovery. 
    Agent uses this to find active hosts on a subnet before attacking them.
    Dynamically excludes friendly infrastructure containers.
    """
    # 1. Define friendly container names based on docker-compose.yml
    friendly_containers = ["threatscope_db", "threatscope_backend", "threatscope_frontend"]
    excluded_ips = []
    
    # 2. Resolve their current IPs using Docker's internal DNS
    for container in friendly_containers:
        try:
            ip = socket.gethostbyname(container)
            excluded_ips.append(ip)
        except socket.gaierror:
            # If a container isn't running or the name is slightly off, skip it safely
            pass

    try:
        # This safely parses "172.18.0.0/24" and finds the first usable IP "172.18.0.1"
        network = ipaddress.IPv4Network(target_subnet, strict=False)
        gateway_ip = str(network[1]) 
        if gateway_ip not in excluded_ips:
            excluded_ips.append(gateway_ip)
    except ValueError:
        # If the user typed a single IP instead of a subnet, just ignore this step
        pass
            
    # 3. Build the Nmap arguments
    nmap_args = '-sn'
    if excluded_ips:
        exclude_str = ",".join(excluded_ips)
        nmap_args += f' --exclude {exclude_str}'
        
    nm = nmap.PortScanner()
    # Execute the scan with the dynamic exclusions
    nm.scan(hosts=target_subnet, arguments=nmap_args)
    
    active_hosts = [host for host in nm.all_hosts() if nm[host].state() == 'up']
    
    # We include the excluded_ips in the output just so you can see it working in the logs!
    return json.dumps({
        "action": "ping_sweep", 
        "active_hosts": active_hosts,
        "ignored_friendly_ips": excluded_ips
    })

def tool_port_scan(target_ip: str) -> str:
    """
    Tool 2: Enumeration. 
    Agent uses this to find open ports and services on a single active IP.
    """
    nm = nmap.PortScanner()
    # -F: Fast scan (top 100 ports), -sV: Probe open ports to determine service/version info
    nm.scan(hosts=target_ip, arguments='-F -sV') 
    
    results = {}
    if target_ip in nm.all_hosts():
        for proto in nm[target_ip].all_protocols():
            for port in nm[target_ip][proto].keys():
                service = nm[target_ip][proto][port].get('name', 'unknown')
                version = nm[target_ip][proto][port].get('version', '')
                results[port] = f"{service} {version}".strip()
                
    return json.dumps({"action": "port_scan", "target": target_ip, "open_ports": results})

def tool_vulners_scan(target_ip: str, port_list: list) -> str:
    """
    Tool 3: Exploitation Assessment. 
    Agent uses this to run the heavy Vulners script ONLY on ports it knows are open.
    """
    if not port_list:
        return json.dumps({"error": "No ports provided for vulnerability scan."})
        
    nm = nmap.PortScanner()
    ports_str = ",".join(map(str, port_list))
    
    # Run the vulners script only on the specified ports
    nm.scan(hosts=target_ip, arguments=f'-p {ports_str} -sV --script vulners')
    
    # Regex to cleanly extract CVE IDs so the Agent doesn't have to read Nmap's raw text
    cve_pattern = re.compile(r"CVE-\d{4}-\d+")
    found_cves = []
    
    if target_ip in nm.all_hosts():
         for proto in nm[target_ip].all_protocols():
             for port in nm[target_ip][proto].keys():
                 script_results = nm[target_ip][proto][port].get('script', {})
                 if 'vulners' in script_results:
                     vuln_text = script_results['vulners']
                     
                     # Extract unique CVEs from the script output
                     cves = list(set(cve_pattern.findall(vuln_text)))
                     if cves:
                         found_cves.append({
                             "port": port,
                             "cves": cves[:10]
                         })
                         
    return json.dumps({"action": "vulners_scan", "target": target_ip, "vulnerabilities": found_cves})