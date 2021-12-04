import sys
import scapy.all as scapy
import socket
from IPy import IP
from scapy.volatile import RandShort

DNS_SERVER_ADDRESS = "192.168.43.1"


def validate_input(args):
    """
    Validate input and return correspondent case

    :param
    input - user input

    :returns
    case:
        reverse - for reverse dns lookup
        regular - for regular dns lookup

    If input is invalid, it will exit
    """
    if len(args) != 2 and len(args) != 3 or sys.argv[1] == "-h":
        print_help()
    elif len(args) == 3:
        try:
            if args[1].lower() != "-type=ptr":
                print_help()
            socket.inet_aton(args[2])
            return "reverse"
        except socket.error:
            print('Not valid IP address')
            exit(0)
    return "regular"


def resolve_hostname(hostname):
    """
    Resolve hostname with dns query and print A and CNAME records

    :param
    hostname - the hostname to resolve

    """
    dns_req = scapy.IP(dst=DNS_SERVER_ADDRESS) / scapy.UDP(sport=RandShort(), dport=53) / scapy.DNS(rd=1,
                                                                                                    qd=scapy.DNSQR(
                                                                                                        qname=hostname))
    answer = scapy.sr1(dns_req, verbose=0, timeout=3)
    if answer is not None:
        if answer.rcode != 3:
            for i in range(answer.ancount):
                if answer.an[i].type == 5:
                    print(f"CNAME is: {str(answer.an[i].rdata, 'utf-8')}")
                else:
                    print(f'IP is: {answer.an[i].rdata}')
        else:
            print(f'IP not found for hostname {hostname}. Is it a valid hostname?')
    else:
        print('Error connecting to DNS server')


def resolve_ip(ip):
    """
    Resolve ip with reverse dns query and print hostname

    :param
    ip - the ip to resolve

    """
    ip_for_query = IP(ip)
    ip_for_query = ip_for_query.reverseName()
    dns_req = scapy.IP(dst=DNS_SERVER_ADDRESS) / scapy.UDP() / scapy.DNS(rd=1,
                                                                         qd=scapy.DNSQR(qname=ip_for_query,
                                                                                        qtype='PTR'))
    answer = scapy.sr1(dns_req, verbose=0, timeout=3)
    if answer is not None:
        if answer.rcode != 3:
            print(f"IP: {ip} is {str(answer.an.rdata, 'utf-8')}")
    else:
        print('Error connecting to DNS server')


def print_help():
    """
    Prints usage message and exit
    """
    print('Usage:\npython nslookup.py <domain>\npython nslookup.py -type=PTR <IP>')
    exit(0)


if __name__ == '__main__':
    lookup_type = validate_input(sys.argv)
    if lookup_type == "regular":
        resolve_hostname(sys.argv[1])
    elif lookup_type == "reverse":
        resolve_ip(sys.argv[2])
