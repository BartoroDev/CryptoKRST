import time
import threading
import socket
import logging
import argparse
from fastapi import FastAPI

from typing import Optional
from enum import Flag
from zlib import adler32

import uvicorn

from pow import Transaction, Block, Blockchain
from wallet import sign_data

TRANSACTIONS_PER_BLOCK = 1

# ------------- PROTOCOL -------------

class Message:
    # |VERSION(1b)|TYPE(1b)|CONTROL(1b)|HASH(4b)|DATA_LENGTH(2b)|DATA|
    class Version(Flag):
        VERSION_ONE = 1

        def toBytes(self):
            return self.value.to_bytes()

    class Type(Flag):
        UNICAST = 1
        BROADCAST = 2

        def toBytes(self):
            return self.value.to_bytes()

    class Control(Flag):
        # *_REQ - request
        # *_ANN - announcement/response
        TRANSACTION_REQ = 1
        TRANSACTION_ANN = 2
        BLOCK_REQ = 3
        BLOCK_ANN = 4
        BLOCKCHAIN_REQ = 5
        BLOCKCHAIN_ANN = 6
        OTHER = 7

        def toBytes(self):
            return self.value.to_bytes()

    def __init__(self, msg: bytes):
        self._raw = msg
        self.version = self.Version(msg[0])
        self.type = self.Type(msg[1])
        self.control = self.Control(msg[2])
        self.hash = int.from_bytes(msg[3:7])
        self.dataLength = int.from_bytes(msg[7:9])
        if (self.dataLength > 0):
            self.data = msg[9:]
        else:
            self.data = bytes()

    def toBytes(self) -> bytes:
        return self.version.toBytes() + self.type.toBytes() + self.control.toBytes() + self.hash.to_bytes(4) + self.dataLength.to_bytes(2, byteorder='big') + self.data

    @classmethod
    def fromData(cls, data: str, version: Version, type: Type, control: Control = Control.OTHER):
        dataLen = len(data)
        print(data)
        hash = adler32(data.encode() + time.ctime().encode())
        raw = version.toBytes() + type.toBytes() + control.toBytes() + hash.to_bytes(4) + dataLen.to_bytes(2) + data.encode()
        return cls(raw)

    @classmethod
    def blockchainRequest(cls):
        hash = adler32(time.ctime().encode())
        raw = cls.Version.VERSION_ONE.toBytes() + cls.Type.UNICAST.toBytes() + cls.Control.BLOCKCHAIN_REQ.toBytes() + hash.to_bytes(4) + int(0).to_bytes(2) + "".encode()
        return cls(raw)



class Queue:
    def __init__(self):
        self._queue = list()
        self._lock = threading.Lock()

    def put(self, item):
        with self._lock:
            self._queue.append(item)

    def pop(self):
        with self._lock:
            ret = self._queue.pop()
        return ret

    def isEmpty(self):
        with self._lock:
            ret = len(self._queue)
        return False if ret > 0 else True


#  ------------- HTTP SERVER -------------

class HTTPServer:
    def __init__(self,  node: "Node", logger: logging.Logger):
        self.app = FastAPI()
        self.node = node
        self.logger = logger

    def addAppRoutes(self):
        # define all routes here
        self.app.add_api_route("/", self.hello, methods=["GET"])
        self.app.add_api_route("/transaction", self.add_transaction, methods=["POST"])


    def hello(self):
        return {"Hello": "World"}

    def add_transaction(self, transaction: Transaction.Model):
        trans = Transaction(transaction.sender, transaction.recipient, transaction.amount)
        if self.node.newTransaction(trans):
            result = "Transaction accepted"
        else:
            result = "Transaction rejected"
        return {"result":result}

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
        self.txQueue = Queue()
        self.socket.setblocking(False)
        self._running = False
        self._lock = threading.Lock()
        self.response = None
        # TODO: add asking if this is node

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
                data = self.socket.recv(1024)
                if not data:
                    self.closeConnection()
                    return

                # TODO: check if message is complete, for long blockchain it will be required!
                msg = Message(data)
                self.processData(msg)
                break
            except BlockingIOError:
                time.sleep(0.5)

    def forwardMessage(self, msg: Message):
        self.txQueue.put(msg)

    def processData(self, msg: Message):
        if msg.type == Message.Type.BROADCAST:
            self.logger.debug("Received broadcast")
            self.node.broadcastMessage(msg)


        if msg.data == b"close":
            self.closeConnection()
            return

        self.logger.debug(f"rx: {msg.toBytes()}")
        self.logger.info(f"RECV ({self.destination[1]}): {msg.data}")
        self.logger.warning(msg.data)

        if msg.control == Message.Control.BLOCKCHAIN_REQ:
            result = Message.fromData(self.node.returnBlockchain().decode(), Message.Version.VERSION_ONE, Message.Type.UNICAST, Message.Control.BLOCKCHAIN_ANN)
            self.txQueue.put(result)
            return

        if msg.control == Message.Control.BLOCKCHAIN_ANN:
            with self._lock:
                self.response = msg.data
            return

        if msg.type != Message.Type.BROADCAST:
            self.txQueue.put(msg)

    def askForBlockchain(self) -> bytes:
        request = Message.blockchainRequest()
        self.forwardMessage(request)
        result = None
        while True: # TODO: some timeout should be applied
            with self._lock:
                if self.response:
                    result = self.response
                    self.response = None
                    break
            time.sleep(0.1)
        return result

class Node:
    def __init__(self, name: str, peers: Optional[list[int]]):
        self.connections = dict[int, Connection]()
        self.name = name
        self.socketServer = self.prepareSocketServer()
        self.logger = self.prepareLogger()
        self.webServer = HTTPServer(self, self.logger)
        self.broadcastedMessages = set[int]()
        self._connId = self.connectionIDGenerator()
        self._condition = threading.Condition()
        self._blockchain = self.prepareBlockchain(peers)

    def prepareBlockchain(self, peers: Optional[list[int]]) -> Blockchain:
        # if peers:
        #     self.connect(peers)
        # return Blockchain()
        if peers:
            self.connect(peers)
            blockchain_data = self.askForBlockchain()
            return Blockchain.fromBytes(blockchain_data)
        else:
            return Blockchain()

    def askForBlockchain(self) -> bytes:
        results = []
        for id, conn in self.connections.items():
            results.append(conn.askForBlockchain())

        # TODO: handle varying blockchains
        return results[0]

    def returnBlockchain(self) -> bytes:
        with self._condition:
            bc_bytes = self._blockchain.toBytes()
        return bc_bytes

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

    def newTransaction(self, transaction: Transaction) -> bool:
        msg = Message.fromData(transaction.toBytes().decode(), Message.Version.VERSION_ONE, Message.Type.BROADCAST, Message.Control.TRANSACTION_ANN)
        self.broadcastMessage(msg)
        with self._condition:
            try:
                transaction.signature = sign_data("my_secure_seed", transaction.hash)
                if self._blockchain.add_transaction(transaction):
                    self._condition.notify()
                    return True
                else:
                    return False
            except ValueError:
                return False

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

    def minerLoop(self):
        with self._condition:
            while True:
                if self._blockchain.get_pending_transactions_count() == TRANSACTIONS_PER_BLOCK:
                    self._blockchain.mine_block_on_blockchain()
                else:
                    self._condition.wait()

    def runMiner(self):
        miner_thread = threading.Thread(target=self.minerLoop)
        miner_thread.start()

    def run(self):
        self.runMiner()
        self.runSocketServer()
        self.runWebServer()

def parseArgs() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--name", default="A", type=str)
    parser.add_argument("--join", nargs="*", type=int)
    return parser.parse_args()


def main():
    args = parseArgs()
    node = Node(args.name, args.join)
    node.run()


if __name__ == "__main__":
    main()
