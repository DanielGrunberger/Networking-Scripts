import os
import socket
import protocol
import pyautogui
import glob
import shutil
import subprocess
import PIL
import shutil


IP = "127.0.0.1"
PHOTO_PATH = r"C:\Users\Grunba\Desktop\screenshot.jpg"  # The path + filename where the screenshot at the server should be saved


def check_client_request(cmd):
    """
    Break cmd to command and parameters
    Check if the command and params are good.

    For example, the filename to be copied actually exists

    Returns:
        valid: True/False
        command: The requested cmd (ex. "DIR")
        params: List of the cmd params (ex. ["c:\\cyber"])
    """
    # Use protocol.check_cmd first
    if protocol.check_cmd(cmd):
        command = cmd.split(" ")
        params = []
        is_valid = True
        if len(command) == 2:
            path = command[1]
            if os.path.exists(path):
                params.append(path)
            else:
                is_valid = False

        elif len(command) == 3:
            path_from = command[1]
            path_to = command[2]
            if os.path.exists(path_from):
                params.append(path_from)
                params.append(path_to)
            else:
                is_valid = False

    else:
        is_valid = False

    return is_valid, command[0], params


def handle_client_request(command, params):
    """Create the response to the client, given the command is legal and params are OK

    For example, return the list of filenames in a directory
    Note: in case of SEND_PHOTO, only the length of the file will be sent

    Returns:
        response: the requested data

    """
    response = ""
    if command == "DIR":
        files_list = glob.glob(str(params[0]) + r'\*.*')
        output = ""
        for file in files_list:
            output += file.replace(str(params[0]), "") + "\n"
        return output

    elif command == "DELETE":
        os.remove(str(params[0]))
        response = f"Deleted {str(params[0])}"

    elif command == "COPY":
        shutil.copy(str(params[0]), str(params[1]))
        shutil.copy(params[0], params[1])
        response = f"Copied {str(params[0])} to {str(params[1])}"

    elif command == "EXECUTE":
        subprocess.call(str(params[0]))
        response = f"Success running {str(params[0])}"

    elif command == "TAKE_SCREENSHOT":
        image = pyautogui.screenshot()
        image.save(PHOTO_PATH)
        response = "Screenshot saved on server"

    elif command == "EXIT":
        response = "Closing connection..."

    return str(response)


def main():
    # open socket with client
    server_socket = socket.socket()
    server_socket.bind(("0.0.0.0", protocol.PORT))
    server_socket.listen()
    print("Server is up and running")
    (client_socket, client_address) = server_socket.accept()
    print("Client connected")

    # handle requests until user asks to exit
    while True:
        # Check if protocol is OK, e.g. length field OK
        valid_protocol, cmd = protocol.get_msg(client_socket)
        if valid_protocol:
            # Check if params are good, e.g. correct number of params, file name exists
            valid_cmd, command, params = check_client_request(cmd)
            if valid_cmd:
                if command == 'SEND_PHOTO':
                    #  Send size of length field
                    size_of_pic = os.path.getsize(PHOTO_PATH)
                    num_of_digits = len(str(size_of_pic))
                    size_msg = protocol.create_msg(str(num_of_digits).zfill(protocol.LENGTH_FIELD_SIZE))
                    client_socket.send(size_msg)
                    #  Send size of picture
                    client_socket.send(str(size_of_pic).encode())
                    #  Send picture
                    try:
                        img = open(PHOTO_PATH, 'rb')
                        image = img.read(size_of_pic)
                        if not image:
                            break
                        client_socket.send(image)
                        img.close()
                    except:
                        client_socket.send(protocol.create_msg("Something went wrong"))
                        return

                else:
                    # prepare a response using "handle_client_request"
                    response = handle_client_request(command, params)
                    # add length field using "create_msg"
                    response = protocol.create_msg(response)
                    # send to client
                    client_socket.send(response)

                if command == 'EXIT':
                    break

            else:
                # prepare proper error to client
                response = 'Bad command or parameters'
                response = protocol.create_msg(response)
                # send to client
                client_socket.send(response)

        else:
            # prepare proper error to client
            response = 'Packet not according to protocol'
            response = protocol.create_msg(response)
            # send to client
            client_socket.send(response)
            # Attempt to clean garbage from socket
            client_socket.recv(1024)

    # close sockets
    print("Closing connection")
    client_socket.close()
    server_socket.close()


if __name__ == '__main__':
    main()

