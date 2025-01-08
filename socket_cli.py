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
    msg = Message("Connected")
    inputed = None
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect(("localhost", port))
        s.settimeout(1)
        clientPort = s.getsockname()[1]
        while True:
            bmsg = msg.toBytes()
            s.sendall(bmsg)
            if inputed == "close":
                break

            try:
                received = s.recv(1024)
                print(f"({s.getpeername()[1]})S: {received!r}")
                receivedMsg = Message.fromBytes(received)
                if receivedMsg.control == Message.Control.PORT_REQUEST:
                    msg = Message.portResponse(clientPort)
                    continue

                if receivedMsg.control == Message.Control.NAME_REQUEST:
                    msg = Message.nameResponse("socket client")
                    continue
            except TimeoutError:
                pass

            inputed = input(f"({clientPort})C: ")
            msgId += 1
            msgType = Message.Type.BROADCAST if inputed[:2] == "b!" else Message.Type.UNICAST
            if msgType == Message.Type.BROADCAST:
                inputed = inputed[2:]
            msg = Message(inputed, type=msgType)


if __name__ == "__main__":
    port = parseArgs()
    main(port)
