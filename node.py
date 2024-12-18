import time
import threading
import socket
import logging
import argparse
from fastapi import FastAPI
from pydantic import BaseModel

from typing import Union
from enum import Flag
from zlib import adler32

import uvicorn


# ------------- PROTOCOL -------------

class Message:
    # |VERSION(1b)|TYPE(1b)|HASH(4b)|DATA_LENGTH(1b)|DATA|
    class Version(Flag):
        VERSION_ONE = 1

        def toBytes(self):
            return self.value.to_bytes()

    class Type(Flag):
        UNICAST = 1
        BROADCAST = 2

        def toBytes(self):
            return self.value.to_bytes()

    def __init__(self, msg: bytes):
        self._raw = msg
        self.version = self.Version(msg[0])
        self.type = self.Type(msg[1])
        self.hash = int.from_bytes(msg[2:6], byteorder='big')
        self.dataLength = int(msg[6])
        self.data = msg[7:]

    def toBytes(self) -> bytes:
        return self.version.toBytes() + self.type.toBytes() + self.hash.to_bytes(4, byteorder='big') + self.dataLength.to_bytes() + self.data

    @classmethod
    def fromData(cls, data: bytes, version: Version, type: Type):
        dataLen = len(data)
        hash = adler32(data + time.ctime().encode())
        raw = version.toBytes() + type.toBytes() + hash.to_bytes(4) + dataLen.to_bytes() + data
        return cls(raw)


class MessageQueue:
    def __init__(self):
        self._queue = list[Message]()
        self._lock = threading.Lock()

    def put(self, message):
        with self._lock:
            self._queue.append(message)

    def pop(self) -> Message:
        with self._lock:
            ret = self._queue.pop()
        return ret

    def isEmpty(self):
        with self._lock:
            ret = len(self._queue)
        return False if ret > 0 else True


#  ------------- HTTP SERVER -------------

class HTTPServer:
    class Transaction(BaseModel):
        signature: str
        signer_public_key: str
        value: str

    def __init__(self,  node: "Node", logger: logging.Logger):
        self.app = FastAPI()
        self.node = node
        self.logger = logger
        self.addAppRoutes()

    def addAppRoutes(self):
        # define all routes here
        self.app.add_api_route("/", self.hello, methods=["GET"])
        self.app.add_api_route("/transaction", self.add_transaction, methods=["POST"])


    def hello(self):
        return {"Hello": "World"}

    def add_transaction(self, transaction: Transaction):
        msgType = Message.Type.BROADCAST if transaction.value[:2] == "b!" else Message.Type.UNICAST
        if (msgType == Message.Type.BROADCAST):
            msg = Message.fromData(transaction.value[2:].encode(), Message.Version.VERSION_ONE, msgType)
            self.node.broadcastMessage(msg)

        return {"received signature":transaction.value}

    def run(self):
        uvicorn.run(self.app, port=0, log_level="debug")


# ------------- SOCKET SERVER / NODE -------------

class Connection:
    def __init__(self, connection: socket.socket, destination, id, node: "Node"):
        self.socket = connection
        self.destination = destination
        self.id = id
        self.msgCount = 0
        self.node = node
        self.logger = node.logger
        self.txQueue = MessageQueue()
        self.socket.setblocking(False)
        self._running = False

    def closeConnection(self):
        self.node.removeConnection(self)
        self.logger.info(f"Closing connection with: {self.destination}")
        self._running = False


    def loop(self):
        self._running = True
        with self.socket:
            self.logger.info(f"Connected with {self.destination}")
            while self._running:
                self.receiveMessage()
                self.sendMessage()
                

    def sendMessage(self):
        if not self.txQueue.isEmpty():
            msg = self.txQueue.pop()
            self.logger.info(f"SEND ({self.destination[1]}): {msg.data}")
            self.logger.debug(f"tx: {msg.toBytes()}")
            self.socket.sendall(msg.toBytes())

    def receiveMessage(self):
        while True:  # receive complete message
            if not self.txQueue.isEmpty():
                break

            try:
                data = self.socket.recv(255)
                if not data:
                    self.closeConnection()
                    return

                msg = Message(data) # TODO: check if message is complete
                self.processData(msg)
                break
            except BlockingIOError:
                time.sleep(0.5)

    def forwardMessage(self, msg: Message):
        self.txQueue.put(msg)

    def processData(self, msg: Message):
        if msg.data == b"close":
            self.closeConnection()
            return

        self.logger.debug(f"rx: {msg.toBytes()}")
        self.logger.info(f"RECV ({self.destination[1]}): {msg.data}")
        if msg.type == Message.Type.BROADCAST:
            self.logger.debug("Received broadcast")
            self.node.broadcastMessage(msg)
        else:
            self.txQueue.put(msg)

class Node:
    def __init__(self, name: str):
        self.connections = dict[int, Connection]()
        self.name = name
        self.socketServer = self.prepareSocketServer()
        self.logger = self.prepareLogger()
        self.webServer = HTTPServer(self, self.logger)
        self.broadcastedMessages = set[int]()
        self._connId = self.connectionIDGenerator()

    def prepareLogger(self):
        webLogger = logging.getLogger("uvicorn.error")
        webLogger.setLevel(logging.DEBUG)

        formatter = logging.Formatter("%(asctime)s %(message)s", datefmt="%m/%d/%Y %I:%M:%S")

        consoleHandler = logging.StreamHandler()
        consoleHandler.setFormatter(formatter)
        consoleHandler.setLevel(logging.INFO)

        logFilename = f"server_{self.name}_{str(self.socketServer.getsockname()[1])}.log"
        fileHandler = logging.FileHandler(logFilename, encoding="utf-8")
        fileHandler.setFormatter(formatter)
        fileHandler.setLevel(logging.DEBUG)

        webLogger.addHandler(consoleHandler)
        webLogger.addHandler(fileHandler)
        return webLogger

    def prepareSocketServer(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind(("localhost", 0))
        server.listen()
        return server

    def broadcastMessage(self, msg: Message):
        if msg.hash not in self.broadcastedMessages:
            self.logger.info("Broadcasting a message")
            self.broadcastedMessages.add(msg.hash)
            for id, conn in self.connections.items():
                self.logger.debug(f"Forward msg to conn id: {id} ({conn.destination})")
                conn.forwardMessage(msg)
        else:
            self.logger.debug("Ignoring broadcast, message already handled")

    def removeConnection(self, conn: Connection):
        self.connections.pop(conn.id)

    def connectionIDGenerator(self):
        connId = 1
        while True:
            yield connId
            connId += 1


    def createConnection(self, conn: socket.socket, addr):
        id = next(self._connId)
        connection = Connection(conn, addr, id, self)
        self.connections[id] = connection
        connThread = threading.Thread(target=connection.loop)
        connThread.start()

    def connect(self, ports: list[int]):
        self.logger.warning(ports)
        for port in ports:
            try:
                cli = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                address = ("localhost", port)
                cli.connect(address)
                self.createConnection(cli, address)
            except ConnectionRefusedError:
                self.logger.info(f"Couldn't connect with {address}")

    def runSocketServer(self):
        def listenForConnections():
            self.logger.info(f"Start socket server {self.name} on port: {self.socketServer.getsockname()[1]}")
            with self.socketServer as s:
                while True:  # wait for connections, some sane upper limit can be applied
                    conn, addr = s.accept()
                    self.createConnection(conn, addr)

        socketServerThread = threading.Thread(target=listenForConnections)
        socketServerThread.start()

    def runWebServer(self):
        self.webServer.addAppRoutes()
        self.webServer.run()


    def run(self):
        self.runSocketServer()
        self.runWebServer()


def parseArgs() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--name", default="A", type=str)
    parser.add_argument("--join", nargs="*", type=int)
    return parser.parse_args()


def main():
    args = parseArgs()
    node = Node(args.name)
    if args.join:
        node.connect(args.join)
    node.run()


if __name__ == "__main__":
    main()
