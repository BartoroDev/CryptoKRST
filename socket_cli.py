import socket
import argparse

from node import Message

HOST = "localhost"

def parseArgs() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("port", type=int)
    args = parser.parse_args()
    return args.port

def main(port):
    msgId = 1
    msg = Message.fromData("Connected", Message.Version.VERSION_ONE, Message.Type.UNICAST)
    inputed = None
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect(("localhost", port))
        while True:
            bmsg = msg.toBytes()
            s.sendall(bmsg)
            if inputed == "close":
                break
            received = s.recv(1024)
            print(f"({s.getpeername()[1]})S: {received!r}")
            inputed = input(f"({s.getsockname()[1]})C: ")
            msgId += 1
            msgType = Message.Type.BROADCAST if inputed[:2] == "b!" else Message.Type.UNICAST
            if msgType == Message.Type.BROADCAST:
                inputed = inputed[2:]
            msg = Message.fromData(inputed, Message.Version.VERSION_ONE, msgType)


if __name__ == "__main__":
    port = parseArgs()
    main(port)
