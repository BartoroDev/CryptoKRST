import argparse
import logging
import signal
import socket
from daemonize import Daemonize
from multiprocessing import Process
from datetime import datetime

def parseArgs() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--init", action="store_true")
    parser.add_argument("--join", type=int)
    return parser.parse_args()


class Node:
    def __init__(self, config: argparse.Namespace):
        self.config = config
        self.server = self.prepareServer()
        self.port = self.server.getsockname()[1]
        self.name = f"node_{self.port}"
        self.pid = f"/tmp/{self.name}.pid"
        self.logger = self.prepareLogger()

    def prepareServer(self) -> socket.socket:
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind(("localhost", 0))
        server.listen()
        return server

    def prepareLogger(self) -> logging.Logger:
        logger = logging.getLogger(__name__)
        logger.setLevel(logging.DEBUG)
        logger.propagate = False
        fh = logging.FileHandler(f"{self.name}.log", "w")
        fh.setLevel(logging.DEBUG)
        logger.addHandler(fh)
        return logger

    def finish(self):
        self.server.close()
        self.logger.warning(f"Miner {self.name} finished working at {datetime.now()}")

    def handleSIGTERM(self, signum, frame):
        self.finish()

    def serve(self):
        with self.server as s:
            while True: # loop through connections
                conn, addr = s.accept()
                with conn:
                    self.logger.info(f"Connected by {addr}")
                    while True: # loop through all data
                        data = conn.recv(1024)
                        if not data:
                            break
                        self.logger.info(f"received: {data}")
                        conn.sendall(data)

    def start(self):
        signal.signal(signal.SIGTERM, self.handleSIGTERM)
        self.logger.info(f"Miner {self.name} started at {datetime.now()}")
        self.logger.debug(f"init config: {self.config.init}")
        if self.config.init:
            self.serve()

def client(port: int):
    msg = "Connected"
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect(("localhost", port))
        while msg != "close":
            s.sendall(msg.encode())
            data = s.recv(1024)
            print(f"({s.getpeername()[1]})S: {data!r}")
            msg = input(f"({s.getsockname()[1]})C: ")

if __name__ == "__main__":
    config = parseArgs()
    node = Node(config)
    print(f"Server listening on port: {node.port}")
    daemon = Process(target=node.start, daemon=True)
    daemon.start()
    if (config.join):
        client(config.join)
    daemon.join()