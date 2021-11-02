"""
Scan ips from file. If ip is on the same network as eth0 iface, use arp scan. Otherwise, ping scan.
You can change the iface. It is made to run in ubuntu.
Need to root privileges and python3
"""
import arg_parser
import scanner


def build_list_from_file(filename):
    ips = []
    with open(filename, "r") as file:
        for line in file:
            if scanner.is_good_ipv4(line):
                ips.append(line.rstrip())
            else:
                print(f'{line} is not a valid IP!')
    return ips


def main():
    valid, filename = arg_parser.validate_input()
    if valid:
        ips = build_list_from_file(filename)
        scanner.scan_ips(ips)


if __name__ == '__main__':
    main()
