import random
import socket

start_port = 8111


def send_encoded(skt, msg):
    print(msg)
    skt.send(str(msg).encode())


def change_port(skt):
    port = random.randrange(8000, 8200)
    send_encoded(skt, port)
    skt.close()
    print('Disconnected')
    return port


def get_msg_from_user():
    msg = input('Enter something:')
    return msg


def send_msg(skt, msg):
    send_encoded(skt, msg)
    print(f'Sending {msg}')


def connect_to_server(skt, p):
    try:
        skt.connect(('127.0.0.1', p))
        return ""
    except Exception as e:
        return e


def start_server(skt, port):
    skt = socket.socket()
    skt.bind(("0.0.0.0", port))
    skt.listen()
    print(f'listening in port {port}')
    return skt


def client_state(skt):
    send_msg(skt, get_msg_from_user())
    return change_port(skt)


def start(is_client):
    port = start_port
    while True:
        skt = socket.socket()
        if is_client:
            connect_to_server(skt, port)
            port = client_state(skt)
            is_client = False
        if not is_client:
            skt = socket.socket()
            skt.bind(("0.0.0.0", port))
            skt.listen()
            print(f'listening in port {port}')
            (client_socket, client_address) = skt.accept()
            print('Client connected')
            msg_from_server = client_socket.recv(1024)
            print(f'Client sent {msg_from_server}')
            port = int(client_socket.recv(4))
            print(f'Client changed to port {port}')
            is_client = True
            skt.close()
