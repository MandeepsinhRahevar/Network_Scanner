import socket
import threading
from ipwhois import IPWhois
from ipwhois.exceptions import IPDefinedError
import whois
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
from queue import Queue
import nmap
import dns.resolver
import networkx as nx
import matplotlib.pyplot as plt

# Define headers and API keys if necessary (replace with actual keys)
HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3'
}
api_key_securitytrails = 'your_securitytrails_api_key'
api_key_virustotal = 'your_virustotal_api_key'

def get_ip(domain):
    try:
        return socket.gethostbyname(domain)
    except socket.gaierror:
        return None

def get_ip_range(ip):
    try:
        obj = IPWhois(ip)
        results = obj.lookup_rdap()
        network_info = results.get('network', {})
        cidr = network_info.get('cidr')
        if cidr:
            return cidr
        start_address = network_info.get('start_address')
        end_address = network_info.get('end_address')
        if start_address and end_address:
            return f"{start_address} - {end_address}"
        return None
    except IPDefinedError:
        print(f"Private IP address detected: {ip}")
        return None
    except Exception as e:
        print(f"Error performing WHOIS lookup: {e}")
        return None

def get_whois_info(domain):
    try:
        w = whois.whois(domain)
        return {
            "Registrar": w.registrar,
            "Creation Date": w.creation_date,
            "Expiration Date": w.expiration_date,
            "Name Servers": w.name_servers
        }
    except Exception as e:
        return f"Error: {e}"

def get_geolocation(ip):
    try:
        response = requests.get(f'http://ipinfo.io/{ip}/json')
        return response.json()
    except requests.RequestException:
        return None

def get_server_info(domain):
    try:
        # Try fetching HTTP headers
        http_response = requests.get(f'http://{domain}', timeout=10, allow_redirects=True)
        server_info = http_response.headers.get('Server')
        if server_info:
            return server_info
        
        # If no server info in HTTP headers, try HTTPS
        https_response = requests.get(f'https://{domain}', timeout=10, allow_redirects=True)
        server_info = https_response.headers.get('Server')
        return server_info
    except requests.RequestException:
        return None

def get_website_structure(domain):
    try:
        url = f'http://{domain}' if not domain.startswith('http') else domain
        response = requests.get(url)
        if response.status_code == 200:
            soup = BeautifulSoup(response.content, 'html.parser')
            links = soup.find_all('a', href=True)
            directory_links = [urljoin(url, link.get('href')) for link in links if link.get('href').endswith('/') and not link.get('href').startswith('#')]
            return list(set(directory_links))
        else:
            print(f"Failed to fetch URL. Status code: {response.status_code}")
            return None
    except requests.RequestException as e:
        print(f"Error fetching URL: {e}")
        return None

def port_scan_worker(queue, target):
    open_ports = []
    while not queue.empty():
        port = queue.get()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        socket.setdefaulttimeout(1)
        if sock.connect_ex((target, port)) == 0:
            open_ports.append(port)
        sock.close()
        queue.task_done()
    return open_ports

def get_subdomains_from_securitytrails(domain, api_key):
    url = f"https://api.securitytrails.com/v1/domain/{domain}/subdomains"
    headers = {'APIKEY': api_key, 'Content-Type': 'application/json'}
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        data = response.json()
        return [f"{subdomain}.{domain}" for subdomain in data['subdomains']]
    return []

def get_subdomains_from_virustotal(domain, api_key):
    url = f"https://www.virustotal.com/vtapi/v2/domain/report"
    params = {'apikey': api_key, 'domain': domain}
    response = requests.get(url, params=params)
    if response.status_code == 200:
        data = response.json()
        return data.get('subdomains', [])
    return []

def get_subdomains_from_crtsh(domain):
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    response = requests.get(url, headers=HEADERS)
    if response.status_code == 200:
        subdomains = set(entry['name_value'] for entry in response.json())
        return list(subdomains)
    return []

def dns_bruteforce(domain):
    common_subdomains = ['www', 'mail', 'ftp', 'test', 'dev', 'api']
    subdomains = []
    for subdomain in common_subdomains:
        try:
            answers = dns.resolver.resolve(f"{subdomain}.{domain}", 'A')
            if answers:
                subdomains.append(f"{subdomain}.{domain}")
        except dns.resolver.NXDOMAIN:
            continue
    return subdomains

def resolve_domain(domain):
    try:
        return socket.gethostbyname_ex(domain)[2]
    except socket.gaierror:
        print(f"Could not resolve IP addresses for {domain}.")
        return []

def scan_network(ip_addresses):
    nm = nmap.PortScanner()
    results = []
    for ip in ip_addresses:
        try:
            nm.scan(ip, arguments='-sV -O')
            for host in nm.all_hosts():
                if 'tcp' in nm[host]:
                    open_ports = nm[host]['tcp'].keys()
                    results.append((host, open_ports))
        except nmap.PortScannerError as e:
            print(f"Error scanning {ip}: {e}")
    return results

def create_topology_graph(ip_addresses, scan_results):
    G = nx.Graph()
    for ip in ip_addresses:
        G.add_node(ip)
    for result in scan_results:
        ip, open_ports = result
        for port in open_ports:
            G.add_edge(ip, f"{ip}:{port}")
    return G

def visualize_topology(graph):
    pos = nx.spring_layout(graph)
    nx.draw(graph, pos, with_labels=True, node_color='skyblue', node_size=1500, font_size=10)
    plt.title("Network Topology Mapping")
    plt.show()

def scan_vulnerabilities(ip):
    nm = nmap.PortScanner()
    print(f"Scanning {ip} for vulnerabilities...")
    nm.scan(ip, arguments='-sV --script=vuln')
    vulnerabilities = []
    for host in nm.all_hosts():
        for proto in nm[host].all_protocols():
            lport = nm[host][proto].keys()
            for port in lport:
                state = nm[host][proto][port]['state']
                name = nm[host][proto][port]['name']
                script = nm[host][proto][port].get('script', {})
                for script_id, script_output in script.items():
                    vulnerabilities.append({
                        'port': port,
                        'name': name,
                        'state': state,
                        'script_id': script_id,
                        'script_output': script_output
                    })
    return vulnerabilities

def display_vulnerabilities(vulnerabilities):
    if not vulnerabilities:
        print("No vulnerabilities found.")
        return
    print(f"{'Port':<8} {'Service':<20} {'State':<10} {'Vulnerability':<30}")
    print("=" * 80)
    for vuln in vulnerabilities:
        print(f"{vuln['port']:<8} {vuln['name']:<20} {vuln['state']:<10} {vuln['script_id']:<30}")
        print(f"{vuln['script_output']}")
        print("-" * 80)

def main():
    while True:
        domain = input("Enter the domain name (or type 'exit' to quit): ")
        if domain.lower() == 'exit':
            break

        print("Select an option:")
        print("1. Domain to IP")
        print("2. Get IP range")
        print("3. Get Domain information")
        print("4. Get Domain Geolocation information")
        print("5. Get Server information")
        print("6. Get Website Directory Structure")
        print("7. Scan for Open Ports")
        print("8. Discover Subdomains")
        print("9. Network Topology Mapping")
        print("10. possible ports Vulnerability")
        
        option = input("Enter the option number: ")
        
        if option == "1":
            print("Resolving IP address...")
            ip = get_ip(domain)
            if not ip:
                print("Could not resolve domain.")
            else:
                print(f"IP address of {domain}: {ip}")
        elif option == "2":
            ip = get_ip(domain)
            if ip:
                ip_range = get_ip_range(ip)
                if ip_range:
                    print(f"IP range for {domain} ({ip}): {ip_range}")
                else:
                    print(f"Could not determine IP range for {domain} ({ip}).")
            else:
                print("Could not resolve domain.")
        elif option == "3":
            whois_info = get_whois_info(domain)
            if isinstance(whois_info, str):
                print(whois_info)
            else:
                print(f"Domain Registration Details for {domain}:")
                for key, value in whois_info.items():
                    print(f"{key}: {value}")
        elif option == "4":
            ip = get_ip(domain)
            if ip:
                geo_info = get_geolocation(ip)
                if geo_info:
                    print("Geolocation details:")
                    for key, value in geo_info.items():
                        print(f"{key.capitalize()}: {value}")
                else:
                    print("Failed to fetch geolocation details.")
            else:
                print("Could not resolve domain.")
        elif option == "5":
            server_info = get_server_info(domain)
            if server_info:
                print(f"Server information for {domain}: {server_info}")
            else:
                print("Failed to fetch server information or the information is not available.")
        elif option == "6":
            directory_structure = get_website_structure(domain)
            if directory_structure:
                print("\nDirectory Structure:")
                for link in directory_structure:
                    print(link)
            else:
                print("Failed to retrieve directory structure.")
        elif option == "7":
            print(f"Scanning open ports for target: {domain}...")
            queue = Queue()
            for port in range(1, 65535):
                queue.put(port)
            open_ports = port_scan_worker(queue, domain)
            if open_ports:
                print("Open ports:")
                print(sorted(open_ports))
            else:
                print("No open ports found.")
        elif option == "8":
            subdomains = set()
            subdomains.update(get_subdomains_from_securitytrails(domain, api_key_securitytrails))
            subdomains.update(get_subdomains_from_virustotal(domain, api_key_virustotal))
            subdomains.update(get_subdomains_from_crtsh(domain))
            subdomains.update(dns_bruteforce(domain))
            if subdomains:
                print(f"Subdomains found for {domain}:")
                for subdomain in sorted(subdomains):
                    print(subdomain)
            else:
                print(f"No subdomains found for {domain}.")
        elif option == "9":
            ip_addresses = resolve_domain(domain)
            if not ip_addresses:
                continue
            scan_results = scan_network(ip_addresses)
            topology_graph = create_topology_graph(ip_addresses, scan_results)
            visualize_topology(topology_graph)
        elif option == "10":
            ip = get_ip(domain)
            vulnerabilities = scan_vulnerabilities(ip)
            display_vulnerabilities(vulnerabilities)
        else:
            print("Invalid option selected.")

if __name__ == "__main__":
    main()
