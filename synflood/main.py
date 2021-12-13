import scapy.all as scapy

FILENAME = 'attackers.txt'


def is_syn_ack_pkt(pkt):
    """
    Check whether it is a SYN-ACK packet
    :param
        pkt - the packet
    :return
        true or false
    """
    return pkt[scapy.TCP].flags == 'SA'


def is_ack_pkt(pkt):
    """
    Check whether it is an  packet containing ACK
    :param
        pkt - the packet
    :return
        true or false
    """
    return 'A' in pkt[scapy.TCP].flags


def add_without_duplicate(item, arr):
    """
    Add item to list only if it's not in there already
    :param
       item - The item to add
       arr - The list
    :return
        The new list
    """
    if item not in arr:
        arr.append(item)
    return arr


def get_attackers(pcap_file):
    """
   Get list of attackers performing SYN FLOOD from pcap file.
    :param
       pcap_file - The pcap file
    :return
        The list of attackers
    """
    syn_acks_received = []  # List of IPs that got SYN-ACK
    acks_sent = []  # List of IPs that replied with ACK
    attackers = []
    pcap = scapy.rdpcap(pcap_file)
    for pkt in pcap:
        if pkt.haslayer(scapy.TCP):
            src_ip = pkt[scapy.IP].src
            dst_ip = pkt[scapy.IP].dst
            if is_syn_ack_pkt(pkt):
                syn_acks_received = add_without_duplicate(dst_ip, syn_acks_received)
            elif is_ack_pkt(pkt):
                acks_sent = add_without_duplicate(src_ip, acks_sent)

    # Attackers are the ones who got SYN_ACK from server and did not respond to it
    for ip in syn_acks_received:
        if ip not in acks_sent:
            attackers = add_without_duplicate(ip, attackers)
    return attackers


def write_attackers_to_file(filename, attackers):
    """
   Write list of attackers to file
    :param
       filename - The  file to write to
       attackers - The list of attackers
    """
    with open(filename, 'w') as f:
        for attacker in attackers:
            f.write(f'{attacker}\n')


if __name__ == '__main__':
    bad_ips = get_attackers("SynFloodSample.pcap")
    write_attackers_to_file(FILENAME, bad_ips)
