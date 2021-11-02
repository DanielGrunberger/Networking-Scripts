import ipaddress, socket, os, scapy.all as scapy

PORTS =  [22,80,443,445,3389]

""""
def port_service_mapping(port, banner):
    if port == 22 and "ssh".lower() in banner:
        return 'ssh'
    if port == 80 and "http".lower() in banner:
        return 'http'
    if port == 443 and "https".lower() in banner:
        return 'https'
    if port == 443 and "http".lower() in banner:
        return 'http'
    if port == 445 and "smb".lower() in banner:
        return 'smb'
    if port == 3389 and "rdp".lower() in banner:
        return 'rdp'
    return 'unknown'
"""

def port_scan(ip, dst_port):
    ans = scapy.sr1(scapy.IP(dst=ip)/scapy.TCP(dport=dst_port, flags="S"), verbose=False, timeout=10)
    if ans != None:
        if ans.haslayer(scapy.TCP):
            if ans.getlayer(scapy.TCP).flags == 0x12:
                print(f'port {dst_port} is open')
                service = service_scan(ip, dst_port)
                if service != None:
                    print('[+] {}:{}\t {}'.format(ip,dst_port,service.decode()))
            elif ans.getlayer(scapy.TCP).flags == 0x14:
                print(f'port {dst_port} is closed')
        else:
            print(f'port {dst_port} is filtered')
    else:
        print(f'port {dst_port} is filtered')


def service_scan(ip, dst_port):
    try:
        s = socket.socket()
        s.settimeout(1)
        s.connect((ip,dst_port))
        result = s.recv(1024)
        s.close()
        return result
    except:
        return


def ping_scan(ip):
    pingr = scapy.IP(dst=ip) / scapy.ICMP()
    ans = scapy.sr1(pingr, timeout=1, verbose=False)
    if ans != None:
        return True
    return False


def arp_scan(ip):
    pkt = scapy.Ether(dst='ff:ff:ff:ff:ff:ff')/ scapy.ARP(pdst=ip)
    ans= scapy.srp1(pkt, timeout=1, verbose=False)
    if ans != None:
        return True
    return False


def is_good_ipv4(s):
    pieces = s.split('.')
    if len(pieces) != 4:
        return False
    try:
        return all(0 <= int(p) < 256 for p in pieces)
    except ValueError:
        return False


def scan_ips(ips_list):
    print('[+] Starting scan...')
    hosts_up = []
    for ip in ips_list:
        if is_same_network(ip):
            if arp_scan(ip):
                print(f"[+] Host {ip} is up!")
                hosts_up.append(ip)
            else:
                print(f"[+] Host {ip} is down!")
        else:
                if ping_scan(ip):
                    print(f"[+] Host {ip} is up!")
                    hosts_up.append(ip)
                else:
                    print(f"[+] Host {ip} is down!")
    for ip in hosts_up:
        print(f'[+] Scanning ports for {ip}...')
        for port in PORTS:
            port_scan(ip, port)


def is_same_network(ip):
    user_ip = os.popen(
        'ip addr show eth0 | grep "\<inet\>" | awk \'{ print $2 }\'').read().strip()
    network_ip = ipaddress.IPv4Network(user_ip, strict=False)
    return ipaddress.IPv4Address(ip) in ipaddress.IPv4Network(network_ip)
