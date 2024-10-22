import socket
import argparse

HOST = "localhost"

def parseArgs() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("port", type=int)
    args = parser.parse_args()
    return args.port

def main(port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, port))
        s.sendall(b"Test message")
        data = s.recv(1024)

    print(f"Received {data!r}")

if __name__ == "__main__":
    port = parseArgs()
    main(port)
