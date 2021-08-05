"""
Protocol configuration file
"""
LENGTH_FIELD_SIZE = 4
PORT = 8820


def check_cmd(data):
    """
    Check if the command is defined in the protocol, including all parameters
    For example, DELETE c:\work\file.txt is good, but DELETE alone is not
    """
    command = data.split(" ")
    if len(command) == 1 and command[0] != "TAKE_SCREENSHOT" and command[0] != "EXIT"\
            and command[0] != "SEND_PHOTO":
        return False

    elif len(command) == 2 and command[0] != "DIR" and command[0] != "DELETE" and command[0] != "EXECUTE":
        return False

    elif len(command) == 3 and command[0] != "COPY":
        return False

    elif len(command) > 3:
        return False

    return True


def create_msg(data):
    """
    Create a valid protocol message, with length field
    """
    msg_length = str(len(data)).zfill(LENGTH_FIELD_SIZE)
    return (msg_length + str(data)).encode()


def get_msg(my_socket):
    """
    Extract message from protocol, without the length field
    If length field does not include a number, returns False, "Error"
    """
    msg_length = my_socket.recv(LENGTH_FIELD_SIZE).decode()
    if msg_length.isdigit():
        msg = my_socket.recv(int(msg_length)).decode()
        return True, msg
    else:
        return False, "Error"

