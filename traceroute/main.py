from scapy.all import *


def main():
    if len(sys.argv) != 2:
        print('Usage: python main.py <domain>')
        exit(1)
    ttl = 0
    icmp_type = "time-exceeded"
    num_of_stations = 0
    pkt = IP(dst=sys.argv[1]) / ICMP()
    while icmp_type == "time-exceeded":
        if ttl != 0 and ans is not None:
            print(f'Passing through {ans[IP].src}...')
        ttl += 1
        pkt[IP].ttl = ttl
        ans = sr1(pkt, verbose=False, timeout=3)
        num_of_stations += 1
        if ans is None:
            icmp_type = "time-exceeded"
        else:
            icmp_type = ICMP.type.i2s[ans[ICMP].type]
    print(f'Passed through {num_of_stations} stations')


if __name__ == '__main__':
    main()
