""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""
NetScan Project

Project Objectives:
1. Network Discovery: Enable the detection of live hosts within a local network by performing an ARP scan. This helps in identifying active devices connected to the same network.
2. Port Scanning: Implement a port scanning feature that detects open ports on network hosts, providing essential information for vulnerability assessment and security audits.
3. Interface Selection & Network Range Detection: Automate the process of selecting a network interface and detecting the network range for scanning based on the local machine’s configuration.
4. Performance Optimization: Improve scanning efficiency by utilizing multithreaded operations for port scanning, significantly reducing the time required for scanning all ports on a host.

Tools Used:
1. Scapy: A powerful Python-based interactive packet manipulation tool. Used for ARP scanning to discover live hosts and SYN scanning to detect open ports on remote systems.
2. psutil: A Python library for retrieving system and network information. It is used to list network interfaces and retrieve the local IP and subnet information.
3. ipaddress: A Python module used for working with IP addresses and networks. It is utilized to compute the local network range based on the system’s IP and subnet mask.
4. concurrent.futures: A module that facilitates parallel execution of tasks. Used to improve the efficiency of port scanning by distributing the tasks across multiple threads.

Methodologies:
1. Network Interface Selection: The user is prompted to select an active network interface from those available on the system. Only interfaces that are currently up and running are shown. The selected interface is then used to perform network operations such as scanning and discovering live hosts.
2. Local Network Range Detection: The tool retrieves the local machine's IP address and subnet mask through psutil. Using this information, the network range is calculated using the ipaddress module, providing the entire address range of the local network.
3. ARP Scan for Live Hosts: An ARP scan is performed to identify live hosts within the network range. This helps in discovering active devices and mapping out the network infrastructure.
The results of the ARP scan include the IP and MAC addresses of the discovered hosts.
4. Port Scanning: A SYN scan (half-open scan) is used to check for open ports on a given host. This scan sends SYN packets to ports, and open ports respond with a SYN-ACK packet.
The tool uses multithreading to scan all ports (1-65535) efficiently. By using concurrent threads, the port scanning process is sped up significantly.
5. Results Display: Once the scanning is complete, the tool displays the live hosts detected on the network, along with the IP and MAC addresses.
It also shows which ports are open on a selected host, which is critical for network security and vulnerability assessment.

Outcomes:
1. Live Host Discovery: The tool successfully identifies and lists active devices within the local network. It displays the IP and MAC addresses of the discovered devices.
2. Port Scan Results: It efficiently scans all ports (1-65535) of a selected host and reports which ones are open. This helps users identify potential entry points for security attacks.
3. Optimized Performance: By using multithreaded execution for port scanning, the tool scans a large number of ports in a short amount of time, making it suitable for both small and large network environments.
4. User-Friendly Interface: The tool offers a command-line interface that guides users through each step, from selecting a network interface to displaying scan results, making it accessible even for users without extensive technical expertise.

Potential Applications:
1. Penetration Testing: Useful for conducting network reconnaissance during security audits to identify vulnerabilities in target networks.
2. Network Administration: Helps network administrators map out the network topology and monitor for open ports that could expose sensitive services.
3. Cybersecurity Research: Provides a practical tool for cybersecurity researchers to analyze network behavior and test for security weaknesses.
""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""

from scapy.all import IP, TCP, sr1, arping, conf, socket
import psutil
import ipaddress
import time
import concurrent.futures

# List and Prompt User to Select an Active Interface
def select_network_interface():
    interfaces = psutil.net_if_addrs()
    stats = psutil.net_if_stats()
    available_interfaces = [iface for iface, stat in stats.items() if stat.isup]  # Only show active (up) interfaces

    if not available_interfaces:
        raise Exception("No active network interfaces found.")

    print("\n[+] Available active network interfaces:")
    for idx, iface in enumerate(available_interfaces, start=1):
        print(f"{idx}. {iface}")

    selected_idx = int(input("\nEnter the number of the interface to use: ")) - 1
    if 0 <= selected_idx < len(available_interfaces):
        selected_iface = available_interfaces[selected_idx]
        print(f"\n[+] Selected interface: {selected_iface}")
        return selected_iface
    else:
        raise Exception("[-] Invalid interface selection.")

# Detect The Network Range Based On Selected Interface
def get_localnet_range(selected_iface):
    interfaces = psutil.net_if_addrs()
    iface_info = interfaces[selected_iface]

    for addr in iface_info:
        if addr.family == socket.AF_INET:
            local_ip = addr.address
            subnet_mask = addr.netmask
            network = ipaddress.IPv4Network(f"{local_ip}/{subnet_mask}", strict=False)
            network_range = str(network)
            print(f"\n[+] Detected network range: {network_range} (IP: {local_ip})")
            return network_range

    raise Exception("No Suitable Network Interface Found")

# Perform ARP Scan To Detect Live Hosts In The Network
def discover_hosts(network_range, iface):
    print(f"\n[+] Discovering hosts in network range: {network_range} on interface {iface}")
    live_hosts = []
    
    ans, _ = arping(network_range, iface=iface, timeout=2, verbose=0)

    for sent, received in ans:
        if received.psrc not in live_hosts:
            live_hosts.append(received.psrc)
            print(f"[+] Host discovered: IP={received.psrc}, MAC={received.hwsrc}")
        else:
            print(f"[-] Duplicate Host Ignored: IP={received.psrc}")
    
    return live_hosts

# Perform Port Scanning On A Specific IP Address
def scan_port(ip, port, iface):
    syn_packet = IP(dst=ip)/TCP(dport=port, flags="S")
    response = sr1(syn_packet, iface=iface, timeout=1, verbose=0)
    if response and response.haslayer(TCP) and response[TCP].flags == "SA":
        return port
    return None

def port_scan(ip, iface):
    print(f"\n[+] Scanning all ports on {ip} using interface {iface}")
    start_time = time.time()

    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:  # Adjust thread count as needed
        futures = {executor.submit(scan_port, ip, port, iface): port for port in range(1, 65536)}
        for future in concurrent.futures.as_completed(futures):
            port = futures[future]
            if future.result():
                print(f"[+] Port {port} is OPEN on {ip}")

    end_time = time.time()
    elapsed_time = end_time - start_time
    print(f"\n[+] Time taken to scan all ports on {ip}: {elapsed_time:.2f} seconds")

if __name__ == "__main__":
    try:
        # Step 1: Select active network interface
        selected_iface = select_network_interface()

        # Step 2: Detect network range based on the selected interface
        local_ip_range = get_localnet_range(selected_iface)

        if local_ip_range:
            # Step 3: Discover hosts in the network
            live_hosts = discover_hosts(local_ip_range, selected_iface)

            if live_hosts:
                # Display all discovered hosts and ask user to select one
                print("\n[+] Available hosts to scan:")
                for idx, host in enumerate(live_hosts, start=1):
                    print(f"{idx}. {host}")

                # Prompt user to select a host for scanning
                selected_idx = int(input("\nEnter the number of the host to scan ports: ")) - 1
                if 0 <= selected_idx < len(live_hosts):
                    selected_host = live_hosts[selected_idx]
                    port_scan(selected_host, selected_iface)
                else:
                    print("[-] Invalid selection.")
            else:
                print("[-] No live hosts found.")
    except Exception as e:
        print(f"Error: {e}")
