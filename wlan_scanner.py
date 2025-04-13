import scapy.all as scapy
import nmap
import socket
from mac_vendor_lookup import MacLookup

mac_lookup = MacLookup()
def discover_devices(network_range):
    print(f"[*] Scanning for devices in {network_range}...")
    arp_request = scapy.ARP(pdst=network_range)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=2, verbose=0)[0]

    devices = []
    for element in answered_list:
        ip = element[1].psrc
        mac = element[1].hwsrc
        try:
            vendor = mac_lookup.lookup(mac)
        except Exception:
            vendor = "Unknown"
        devices.append({'ip': ip, 'mac': mac, 'vendor': vendor})
        print(f"[+] Found Device - IP: {ip} | MAC: {mac} | Vendor: {vendor}")
    return devices

def scan_ports(ip):
    print(f"[*] Scanning ports on {ip}...")
    scanner = nmap.PortScanner()
    scanner.scan(ip, '20-1024')  # Common ports range
    for proto in scanner[ip].all_protocols():
        ports = scanner[ip][proto].keys()
        for port in ports:
            state = scanner[ip][proto][port]['state']
            print(f"    Port {port}/{proto} is {state}")
import socket

def get_local_network_range():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # This doesn't need to be reachable; just used to determine interface
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
    except Exception:
        local_ip = "127.0.0.1"
    finally:
        s.close()

    print(f"[*] Detected local IP: {local_ip}")

    ip_parts = local_ip.split('.')
    ip_range = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/24"
    print(f"[*] Using network range: {ip_range}")
    return ip_range
if __name__ == "__main__":
    target_range = get_local_network_range()
    found_devices = discover_devices(target_range)

    for device in found_devices:
        scan_ports(device['ip'])












