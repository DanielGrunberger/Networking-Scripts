from ipaddress import ip_address

from scapy.all import *

HTTP_REQUEST_LENGTH = 8000
LOCAL_IP = "0.0.0.0"
PORT = 8153
SOCKET_TIMEOUT = 20
DNS_SERVER_ADDRESS = "8.8.8.8"
REVERSE_QUERY_PATH = "reverse/"
REVERSE_TYPE = "PTR"
INVALID_IP_CODE = "invalid ip"

"""
Daniel Grunberger
ID: 522883
Grade: 100
"""


def resolve_ip(ip):
    """
    Resolve ip with reverse dns query
    :param
        ip - the ip to resolve
    :returns
        hostnames
    """
    ip_for_query = ip_address(ip).reverse_pointer
    dns_req = IP(dst=DNS_SERVER_ADDRESS) / UDP() / DNS(rd=1,
                                                       qd=DNSQR(qname=ip_for_query,
                                                                qtype='PTR'))
    answer = sr1(dns_req, verbose=0, timeout=3)
    hostnames = []
    if answer is not None:
        if answer.rcode != 3:
            # loop for hostnames
            for i in range(answer.ancount):
                hostnames.append(answer.an.rdata.decode())
            # show one per line
            hostname_list_string = '\n'.join(hostnames)
            return hostname_list_string
    else:
        return 'Error connecting to DNS server'


def resolve_hostname(hostname):
    """
    Resolve hostname with dns query
    :param
        hostname - the hostname to resolve
    :returns
        list of A records or error
    """
    dns_req = IP(dst=DNS_SERVER_ADDRESS) / UDP(sport=RandShort(), dport=53) / DNS(rd=1, qd=DNSQR(qname=hostname))
    answer = sr1(dns_req, verbose=0, timeout=3)
    ips = []
    if answer is not None:
        if answer.rcode != 3:
            for i in range(answer.ancount):
                if answer.an[i].type == 1:
                    ips.append(answer.an[i].rdata)
            # show one per line
            ip_list_string = '\n'.join(ips)
            return ip_list_string
        else:
            return f'IP not found for hostname {hostname}. Is it a valid hostname?'
    else:
        return 'Error connecting to DNS server'


def validate_request_type(resource):
    """
    Validate dns request type according to url
    :param
        resource - the url
    :returns
        dns query type
    """
    if resource.startswith(REVERSE_QUERY_PATH):
        return REVERSE_TYPE
    else:
        return "A"


def is_valid_ip(ip):
    """
    Validate ip address
    :param
        ip - the ip
    :returns
        True if valid, False if not
    """
    try:
        socket.inet_aton(ip)
        return True
    except socket.error:
        return False


def handle_client_request(resource, client_socket):
    """
    Handle http request and send response
    :param
        resource - the resource the client requested
        client_socket - the client socket
    """
    # Return usage for root path
    if resource == '':
        resp = "For hostname lookup: /<domain>\nFor reverse lookup: /reverse/<ip>"
    else:
        dns_type = validate_request_type(resource)
        if dns_type == REVERSE_TYPE:
            ip = resource.split('/')[-1]  # reverse/<ip>
            if is_valid_ip(ip):
                resp = resolve_ip(ip)
            else:
                resp = INVALID_IP_CODE
        # dns_type = 'A'
        else:
            resp = resolve_hostname(resource)
    send_http_resp(resp, client_socket)


def send_http_resp(resp, client_socket):
    """
    Send http request in current client socket
    :param
    resp - response content
    client_socket - current client socket
    """
    http_header = "HTTP/1.1 200 OK\r\n"
    http_header += "Content-Type: text/plain; charset=utf-8\r\n\r\n"
    http_response = (http_header + resp).encode()
    client_socket.send(http_response)


def validate_http_request(request):
    """
    Valid http request
    :param
    request - the http request
    :returns
    True if valid, False if not
    """
    first_line = request.partition("\n")[0].split(" ")
    if first_line[0] == "GET" and "/" in first_line[1] and first_line[2] == "HTTP/1.1\r":
        return True, first_line[1].replace('/', '', 1)
    else:
        return False, ''


def handle_client(client_socket):
    """
    Handle http request coming in client socket
    :param
    client_socket - the client socket
    """

    print('Client connected')
    while True:
        client_request = str(client_socket.recv(HTTP_REQUEST_LENGTH).decode())
        valid_http, resource = validate_http_request(client_request)
        if valid_http:
            print('Got a valid HTTP request')
            handle_client_request(resource, client_socket)
            break
        else:
            print('Error: Not a valid HTTP request')
            break

    print('Closing connection')
    client_socket.close()


def main():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # TCP socket
    try:
        server_socket.bind((LOCAL_IP, PORT))
        server_socket.listen()
    except OSError:
        print('Port taken')
        exit(0)
    print("Listening for connections on port {}".format(PORT))
    while True:
        client_socket, client_address = server_socket.accept()
        print('New connection received')
        client_socket.settimeout(SOCKET_TIMEOUT)
        handle_client(client_socket)


if __name__ == '__main__':
    main()
