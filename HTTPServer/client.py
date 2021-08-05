
import socket
import protocol


IP = "127.0.0.1"
SAVED_PHOTO_LOCATION = r"C:\Users\Grunba\Desktop\client_screenshot.jpg"  # The path + filename where the copy of the
# screenshot at the client should be saved


def handle_server_response(my_socket, cmd):
    """
    Receive the response from the server and handle it, according to the request
    For example, DIR should result in printing the contents to the screen,
    Note- special attention should be given to SEND_PHOTO as it requires an extra receive
    """
    valid_protocol, msg = protocol.get_msg(my_socket)
    command = cmd.split(" ")
    if valid_protocol:
        if command[0] == "SEND_PHOTO":
            msg_length_size = msg
            picture_length_field = my_socket.recv(int(msg_length_size)).decode()
            fp = open(SAVED_PHOTO_LOCATION, 'wb')
            pic = my_socket.recv(int(picture_length_field))
            fp.write(pic)
            fp.close()
            print(f"Screenshot saved to {SAVED_PHOTO_LOCATION}")

        else:
            print(msg)

    else:
        print("Response from server is not following the protocol")


def main():
    # open socket with the server
    my_socket = socket.socket()
    my_socket.connect((IP, protocol.PORT))

    # print instructions
    print('Welcome to remote computer application. Available commands are:\n')
    print('TAKE_SCREENSHOT\nSEND_PHOTO\nDIR\nDELETE\nCOPY\nEXECUTE\nEXIT')

    # loop until user requested to exit
    while True:
        cmd = input("Please enter command:\n")
        if protocol.check_cmd(cmd):
            #  create msg according to protocol
            packet = protocol.create_msg(str(cmd))
            my_socket.send(packet)
            #  handle response
            handle_server_response(my_socket, cmd)
            if cmd == 'EXIT':
                break
        else:
            print("Not a valid command, or missing parameters\n")

    my_socket.close()


if __name__ == '__main__':
    main()