
import socket
import os

IP = "0.0.0.0"
PORT = 80
SOCKET_TIMEOUT = 20
HTTP_REQUEST_LENGTH = 8000  # 8 KB
ROOT_PATH = r"C:\Users\DanielGrunberger\Documents\Machon Lev\networking\HTTP\HTTP\webroot"
DEFAULT_URL = ROOT_PATH + r"\index.html"
FORBIDDEN_PATHS = {r'/robots.txt', r'/credentials.txt'}
REDIRECTION_DICTIONARY = {r'/page1.html': r'/page2.html', '/resource.txt': '/resources.txt'}
CALCULATE_NEXT_PATH = "/calculate-next?num="


def get_file_data(filename):
    """ Get data from file . Return in bytes"""
    file = open(filename, 'rb')
    file_data = file.read()
    file.close()
    return file_data


def handle_client_request(resource, client_socket):
    """ Check the required resource, generate proper HTTP response and send to client"""
    filetype = ''
    # Forbidden resources
    if resource in FORBIDDEN_PATHS:
        http_response = "HTTP/1.1 403 Forbidden\r\n".encode()
    # Moved resources
    elif resource in REDIRECTION_DICTIONARY:
        http_response = ("HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1" + REDIRECTION_DICTIONARY.get(resource) +
                         "\r\n").encode()
    elif resource.startswith(CALCULATE_NEXT_PATH):
        num = resource.split("num=")[-1]
        resp = f"{str(int(num)+1)}\r\n"
        http_header = "HTTP/1.1 200 OK\r\n"
        http_header += "Content-Type: text/html; charset=utf-8\r\n\r\n"
        http_response = (http_header + resp).encode()

    else:
        if resource == '/':  # / --> index.html
            url = DEFAULT_URL
            filetype = 'html'
        else:  # Build path on server
            url = ROOT_PATH + resource
            url = url.replace("/",  '\\')
        http_header = "HTTP/1.1 200 OK\r\n"
        filename = url

    # extract requested file type from URL (html, jpg etc)
        if resource != '/' or resource.startswith(CALCULATE_NEXT_PATH):
            filetype = resource.split(".")[-1]

    # Build content-type header
        if filetype == 'html' or filetype == 'text' or filetype == 'txt':
            content_header = "Content-Type: text/html; charset=utf-8\r\n\r\n"
        elif filetype == 'jpg' or filetype == 'ico':
            content_header = "Content-Type: image/jpeg\r\n\r\n"
        elif filetype == 'css':
            content_header = "Content-Type: text/css\r\n\r\n"
        elif filetype == 'js':
            content_header = "Content-Type: text/javascript; charset=utf-8\r\n\r\n"
        #  Unknown file type
        else:
            if not os.path.isfile(filename):
                http_response = "HTTP/1.1 404 Not Found".encode()
            else:
                http_response = "HTTP/1.1 500 Internal Server Error\r\n".encode()
            client_socket.send(http_response)
            return

        try:
            if not os.path.isfile(filename):
                http_response = "HTTP/1.1 404 Not Found".encode()
            #  Resources that are sent in plaintext
            else:
                data = get_file_data(filename)
                len_header = "Content-Length: " + str(len(data)) + "\r\n"
                http_header += len_header + content_header
                http_response = http_header.encode() + data
        except Exception as e:
            http_response = "HTTP/1.1 500 Internal Server Error\r\n".encode()
            client_socket.send(http_response)
            print(e)
    client_socket.send(http_response)


def validate_http_request(request):
    """ Check if request is a valid HTTP request and returns TRUE / FALSE and the requested URL """
    first_line = request.partition("\n")[0].split(" ")
    if first_line[0] == "GET" and "/" in first_line[1] and first_line[2] == "HTTP/1.1\r":
        return True, first_line[1]
    else:
        return False, ''


def handle_client(client_socket):
    """ Handles client requests: verifies client's requests are legal HTTP, calls function to handle the requests """

    print('Client connected')
    while True:
        # TO DO: insert code that receives client request
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
    # Open a socket and loop forever while waiting for clients
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # AF_INET for ipv4, TCP socket
    try:
        server_socket.bind((IP, PORT))
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


if __name__ == "__main__":
    # Call the main handler function
    main()
