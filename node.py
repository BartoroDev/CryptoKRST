import time
import threading
import socket
import logging
import argparse
import sys, json
from fastapi import FastAPI
from copy import deepcopy

from typing import Optional, Union
from enum import Flag
from zlib import adler32

import uvicorn

from pow import Transaction, Blockchain, Block
from wallet import get_public_key_from_pk

TRANSACTIONS_PER_BLOCK = 2


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
        TRANSACTION_ANN = 1
        BLOCK_ANN = 2
        BLOCKCHAIN_REQ = 3
        BLOCKCHAIN_ANN = 4
        ECHO = 5
        OTHER = 6

        def toBytes(self):
            return self.value.to_bytes()

    def __init__(self, data: Union[str, bytes], *, version: Version = Version.VERSION_ONE, type: Type = Type.UNICAST, control: Control = Control.OTHER, hash: int = 0):
        self.version = version
        self.type = type
        self.control = control
        if isinstance(data, str):
            self.data = data.encode()
        else:
            assert isinstance(data, bytes)
            self.data = data

        self.hash = adler32(self.data) if not hash else hash
        self.dataLength = len(data)
        self.sender = None


    def toBytes(self) -> bytes:
        return self.version.toBytes() + self.type.toBytes() + self.control.toBytes() + self.hash.to_bytes(4) + self.dataLength.to_bytes(2, byteorder='big') + self.data

    @classmethod
    def fromBytes(cls, msg: bytes):
        version = cls.Version(msg[0])
        type = cls.Type(msg[1])
        control = cls.Control(msg[2])
        hash = int.from_bytes(msg[3:7])
        dataLength = int.from_bytes(msg[7:9])
        assert dataLength == len(msg[9:])
        if dataLength > 0:
            data = msg[9:].decode()
        else:
            data = ""
        return cls(data, version=version, type=type, control=control, hash=hash)

    @classmethod
    def blockchainRequest(cls):
        return cls("", control=cls.Control.BLOCKCHAIN_REQ)

    @classmethod
    def blockchainAnnouncement(cls, data):
        return cls(data, control=cls.Control.BLOCKCHAIN_ANN)

    @classmethod
    def blockAnnouncement(cls, data):
        return cls(data, type=cls.Type.BROADCAST, control=cls.Control.BLOCK_ANN)

    @classmethod
    def transactionAnnouncement(cls, data):
        return cls(data, type=cls.Type.BROADCAST, control=cls.Control.TRANSACTION_ANN)



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
        self.app.add_api_route("/blockchain", self.get_blockchain, methods=["GET"])
        self.app.add_api_route("/public_key", self.get_public_key, methods=["GET"])
        self.app.add_api_route("/transactions", self.get_transactions, methods=["GET"])
        self.app.add_api_route("/transaction", self.add_transaction, methods=["POST"])
        self.app.add_api_route("/connections", self.get_connections, methods=["GET"])

    def hello(self):
        return {"Hello": "World"}

    def get_blockchain(self):
        self.node._blockchain = self.node.prepareBlockchain()
        if self.node._blockchain is None:
            return({})
        result = self.node.returnBlockchainObj()
        return result.as_dict()

    def get_connections(self):
        result = self.node.connections
        connections_serializable = {
        key: conn.as_dict() for key, conn in result.items()
        }   
        return json.dumps(connections_serializable)
    
    def get_public_key(self):
        if self.node._blockchain is None:
            return({})
        return {"public_key":str(get_public_key_from_pk(self.node.wallet_key))}

    def get_transactions(self):
        if self.node.wallet_key == "":
            return {"result": "Not mining, exited gracefuly"}
        if self.node._blockchain is None:
            return({})
        transactions = self.node.returnAwaitingTransactions()
        if not transactions:
            return {"transactions": "empty"}
        else:
            return {str(id): x.as_dict() for id, x in enumerate(transactions)}

    def add_transaction(self, transaction: Transaction.Model):
        trans = Transaction(transaction.sender, transaction.recipient, transaction.amount)
        trans.timestamp = transaction.timestamp
        trans.signature = transaction.signature
        trans.hash = transaction.hash
        if self.node.newTransaction(trans):
            result = "Transaction accepted"
        else:
            result = "Transaction rejected"
        if self.node.wallet_key == "":
            result = "Not mining, transaction forwarded"
        return {"result": result}

    def run(self):
        uvicorn.run(self.app, port=0, log_level=logging.INFO)


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
    
    def as_dict(self):
        return {
            "id": self.id,
            "destination": self.destination,
            # Exclude non-serializable attributes like socket
            "node_name": self.node.name if self.node else None  # Example transformation
        }

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
                data = self.socket.recv(102400)# TODO: check if message is complete, for long blockchain it will be required!
                if not data:
                    self.closeConnection()
                    return
                # TODO: check if message is complete, for long blockchain it will be required!
                msg = Message.fromBytes(data)
                ip, port = self.socket.getsockname()
                msg.source = port
                
                self.processData(msg)
                break
            except BlockingIOError:
                time.sleep(0.5)
            except ConnectionResetError:
                self.node.removeConnection(self)

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

        if msg.control == Message.Control.BLOCKCHAIN_REQ:
            blockchain_bytes = self.node.returnBlockchainBytes()
            if blockchain_bytes == None:
                return
            result = Message.blockchainAnnouncement(blockchain_bytes)
            self.txQueue.put(result)
            return

        if msg.control == Message.Control.BLOCKCHAIN_ANN:
            with self._lock:
                self.response = msg.data
            return

        if msg.control == Message.Control.TRANSACTION_ANN:
            trans = Transaction.fromBytes(msg.data)
            self.node.newTransaction(trans)
            return

        if msg.control == Message.Control.BLOCK_ANN:
            block = Block.fromBytes(msg.data)
            self.node.receivedBlock(block)
            return

        if msg.control == Message.Control.ECHO:
            self.txQueue.put(msg)

    def askForBlockchain(self, timeout: int = 10) -> Optional[bytes]:
        request = Message.blockchainRequest()
        self.forwardMessage(request)

        start_time = time.time()
        result = None
        while time.time() - start_time < timeout:  # Wait for a response within the timeout period
            with self._lock:
                if self.response:
                    result = self.response
                    self.response = None
                    break
            time.sleep(0.1)

        if not result:
            self.logger.warning(f"Timeout occurred while waiting for blockchain response from {self.destination}") #TODO: check why it sometimes timeouts
        return result

class Node:
    def __init__(self, name: str, peers: Optional[list[int]], pk:str):
        self.peers=peers #initial peers dont confuse with connections
        self.wallet_key=pk
        self.connections = dict[int, Connection]()
        self.name = name
        self.socketServer = self.prepareSocketServer()
        self.logger = self.prepareLogger()
        self.webServer = HTTPServer(self, self.logger)
        self.broadcastedMessages = set[int]()
        self._connId = self.connectionIDGenerator()
        self._condition = threading.Condition()
        self._blockchain = None

    def prepareBlockchain(self) -> Blockchain:
        if not self.connections and self._blockchain is not None and self.wallet_key != "":
            return self._blockchain

        #not mining no connections
        if self.wallet_key == "" and not self.connections:
            return None
        
        #mining no connections
        if self.wallet_key != "" and not self.connections:
            miner_public_key = get_public_key_from_pk(self.wallet_key)
            return Blockchain(miner_public_key)
    
        blockchain_data = self.updateBlockchain()
        if blockchain_data == None:
            return self._blockchain
        #not mining
        if self.wallet_key == "": 
            return Blockchain.fromBytes(None, blockchain_data)
        #mining
        else:
            miner_public_key = get_public_key_from_pk(self.wallet_key)
            return Blockchain.fromBytes(miner_public_key, blockchain_data)

    def updateBlockchain(self) -> bytes:
        results = []
        for id, conn in self.connections.items(): #pull blockchain from all connections
            results.append(conn.askForBlockchain())

        # TODO: handle varying blockchains
        s = sys.getsizeof(self._blockchain)
        for r in results:
            if sys.getsizeof(r) > s: #return bigger chain or None
                return r
        return None

    def returnBlockchainBytes(self) -> bytes:
        if self._blockchain == None:
            return
        with self._condition:
            bc_bytes = self._blockchain.toBytes()
        return bc_bytes

    def returnBlockchainObj(self) -> Blockchain:

        with self._condition:
            result = deepcopy(self._blockchain)
        return result

    def returnAwaitingTransactions(self):
        with self._condition:
            transactions = deepcopy(self._blockchain.pending_transactions)
        return transactions

    def prepareLogger(self):
        logger = logging.getLogger()
        logger.setLevel(logging.DEBUG)

        formatter = logging.Formatter("%(asctime)s - %(message)s", datefmt="%m/%d/%Y %I:%M:%S")

        consoleHandler = logging.StreamHandler()
        consoleHandler.setFormatter(formatter)
        consoleHandler.setLevel(logging.INFO)

        logFilename = f"server_{self.name}_{str(self.socketServer.getsockname()[1])}.log"
        fileHandler = logging.FileHandler(logFilename, encoding="utf-8")
        fileHandler.setFormatter(formatter)
        fileHandler.setLevel(logging.DEBUG)

        logger.addHandler(consoleHandler)
        logger.addHandler(fileHandler)

        return logger

    def prepareSocketServer(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind(("localhost", 0))
        server.listen()
        return server

    def newTransaction(self, transaction: Transaction) -> bool:
        msg = Message.transactionAnnouncement(transaction.toBytes())
        self.broadcastMessage(msg)
        if self.wallet_key == "": #if not mining dont add transaction
            return False
        with self._condition:
            try:
                if self._blockchain.add_transaction(transaction):
                    self._condition.notify()
                    return True
                else:
                    return False
            except ValueError:
                return False

    def receivedBlock(self, block: Block):
        if self._blockchain.try_add_block(block):
            self.logger.info("Received correct block")
            # TODO: get reward for block verification
        else:
            self.logger.warning(f"Received incorrect block:\n{block}")

    def broadcastMessage(self, msg: Message):
        if msg.hash not in self.broadcastedMessages: 
            self.logger.info(f"Broadcasting a message {msg.hash}")
            self.broadcastedMessages.add(msg.hash)
            for id, conn in self.connections.items():
                if conn.destination == msg.sender:  # Skip sending back to the origin peer TODO
                    continue
                self.logger.debug(f"Forward msg to conn id: {id} ({conn.destination})")
                conn.forwardMessage(msg)
        else:
            self.logger.debug("Ignoring broadcast, message already handled")

    def removeConnection(self, conn: Connection):
        with self._condition:
            self.connections.pop(conn.id, None)

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
                if self._blockchain.max_transactions_per_block():
                    if self._blockchain.mine_block_on_blockchain():
                        msg = Message.blockAnnouncement(self._blockchain.get_latest_block().toBytes())
                        self.broadcastMessage(msg)
                else:
                    self._condition.wait()

    def runMiner(self):
        miner_thread = threading.Thread(target=self.minerLoop)
        miner_thread.start()


    #if miner wallet key is empty, run node in relay mode
    #relay mode: collect blockchain from peers, dont try to add transactions, broadcast incoming transactions
    #miner mode: add transactions to blockchain
    def run(self):
        if self.peers: #first create connections to peers
            self.connect(self.peers)
        self._blockchain = self.prepareBlockchain()
        if self.wallet_key != "":
            self.runMiner()
        self.runSocketServer()
        self.runWebServer()

def parseArgs() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--wallet_key", default="7e01f59d8d4793e62ab05b9cd9c3689fb62cbfd86280f677faf41c40181ea2b7", type=str)
    #parser.add_argument("--wallet_key", default="", type=str) 
    parser.add_argument("--name", default="A", type=str)
    parser.add_argument("--join", nargs="*", type=int)
    return parser.parse_args()

def main():
    args = parseArgs()
    node = Node(args.name, args.join, args.wallet_key)
    node.run()


if __name__ == "__main__":
    main()
