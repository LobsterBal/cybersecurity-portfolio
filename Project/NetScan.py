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
