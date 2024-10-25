import socket
import argparse

HOST = "localhost"

def parseArgs() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("port", type=int)
    args = parser.parse_args()
    return args.port

def main(port):
    msg = "Connected"
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, port))
        while msg != "close":
            s.sendall(msg.encode())
            data = s.recv(1024)
            print(f"({s.getpeername()[1]})S: {data!r}")
            msg = input(f"({s.getsockname()[1]})C: ")

if __name__ == "__main__":
    port = parseArgs()
    main(port)
