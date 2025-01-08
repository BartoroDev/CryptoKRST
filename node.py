import time
import threading
import socket
import logging
import argparse
import sys
from fastapi import FastAPI
from copy import deepcopy

from typing import Optional, Union
from enum import IntEnum
from zlib import adler32

import uvicorn

from pow import Transaction, Blockchain, Block
from wallet import get_public_key_from_pk

TRANSACTIONS_PER_BLOCK = 2


# ------------- PROTOCOL - MESSAGES IMPLEMENTATION -------------

class Message:
    # |VERSION(1b)|TYPE(1b)|CONTROL(1b)|HASH(4b)|DATA_LENGTH(2b)|DATA|
    HEADER_LENGTH=9
    class Version(IntEnum):
        VERSION_ONE = 1

    class Type(IntEnum):
        UNICAST = 1
        BROADCAST = 2

    class Control(IntEnum):
        ECHO = 0
        OTHER = 1
        TRANSACTION_ANNOUNCEMENT = 2
        BLOCK_ANNOUNCEMENT = 3
        BLOCKCHAIN_REQUEST = 4
        BLOCKCHAIN_RESPONSE = 5
        PORT_REQUEST = 6
        PORT_RESPONSE = 7
        NAME_REQUEST = 8
        NAME_RESPONSE = 9

    def __init__(self, data: Union[str, bytes], *, version: Version = Version.VERSION_ONE, type: Type = Type.UNICAST, control: Control = Control.ECHO, hash: int = 0):
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
        return self.version.to_bytes(1) + self.type.to_bytes(1) + self.control.to_bytes(1) + self.hash.to_bytes(4) + self.dataLength.to_bytes(2) + self.data

    @classmethod
    def fromBytes(cls, msg: bytes):
        version = cls.Version.from_bytes(msg[0:1])
        type = cls.Type.from_bytes(msg[1:2])
        control = cls.Control.from_bytes(msg[2:3])
        hash = int.from_bytes(msg[3:7])
        dataLength = int.from_bytes(msg[7:9])
        assert len(msg[9:]) >= dataLength, f"""
            HEADER:\t{msg[:9].hex()}
            DATA:\t{msg[9:].hex()}
            EXPECTED DATA_LEN:\t{dataLength}
            ACTUAL DATA_LEN:\t{len(msg[9:])}
            """
        if dataLength > 0:
            data = msg[9:(9+dataLength)]
        else:
            data = ""
        return cls(data, version=version, type=type, control=control, hash=hash)

    @classmethod
    def blockchainRequest(cls):
        return cls("", control=cls.Control.BLOCKCHAIN_REQUEST)

    @classmethod
    def blockchainResponse(cls, data):
        return cls(data, control=cls.Control.BLOCKCHAIN_RESPONSE)

    @classmethod
    def blockAnnouncement(cls, data):
        return cls(data, type=cls.Type.BROADCAST, control=cls.Control.BLOCK_ANNOUNCEMENT)

    @classmethod
    def transactionAnnouncement(cls, data):
        return cls(data, type=cls.Type.BROADCAST, control=cls.Control.TRANSACTION_ANNOUNCEMENT)

    @classmethod
    def portRequest(cls):
        return cls("", control=cls.Control.PORT_REQUEST)

    @classmethod
    def portResponse(cls, port: int):
        return cls(int.to_bytes(port, 4), control=cls.Control.PORT_RESPONSE)

    @classmethod
    def nameRequest(cls):
        return cls("", control=cls.Control.NAME_REQUEST)

    @classmethod
    def nameResponse(cls, name: str):
        return cls(name, control=cls.Control.NAME_RESPONSE)


class Queue:
    def __init__(self):
        self._queue = list[Message]()
        self._lock = threading.Lock()

    def put(self, item):
        with self._lock:
            self._queue.append(item)

    def pop(self) -> Message:
        with self._lock:
            ret = self._queue.pop()
        return ret

    def isEmpty(self):
        with self._lock:
            ret = len(self._queue)
        return False if ret > 0 else True


#  ------------- HTTP SERVER (REST API) -------------

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
        connections_dict = {
            "node name": self.node.name,
            "node port": self.node.socketServerPort,
            "connections": [connection.as_dict() for connection in self.node.connections.values()]
        }
        return connections_dict
    
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
        uvicorn.run(self.app, port=0, log_level=logging.DEBUG)


# ------------- CONNECTIONS AND MESSAGE PROCESSING -------------

class Connection:
    def __init__(self, connection: socket.socket, destination, id, node: "Node", serverPort = 0):
        self.socket = connection
        self.destination = destination  # separate socket connection destination for connected server
        self.destinationNodePort = serverPort  # port on which the connected server listens for connections
        self.destinationNodeName = ""
        self.id = id
        self.msgCount = 0
        self.node = node
        self.logger = node.logger
        self.txQueue = Queue()
        self.socket.setblocking(False)
        self._running = False
        self._lock = threading.Lock()
        self.response = None

    def sendMessage(self, msg: Message):
        self.txQueue.put(msg)

    # TODO: move this function to node class
    def askForBlockchain(self, timeout: int = 10) -> Optional[bytes]:
        request = Message.blockchainRequest()
        self.sendMessage(request)

        start_time = time.time()
        result = None
        while time.time() - start_time < timeout and self._running:  # Wait for a response within the timeout period
            with self._lock:
                if self.response:
                    result = self.response
                    self.response = None
                    break
            time.sleep(0.1)

        if not result:
            failReason = "Timeout" if time.time() < (start_time + timeout) else "connection error"
            self.logger.warning(f"Fetching blockchain response failed from {self.destinationNodePort} failed, reason: {failReason}")  #TODO: check why it sometimes timeouts

        return result

    def as_dict(self):
        return {
            "connection id": self.id,
            "destination node name": self.destinationNodeName,
            "destination node port": self.destinationNodePort
        }

    def closeConnection(self):
        self.node.removeConnection(self)
        self._running = False
        self.logger.info(f"Closing connection with: {self.destinationNodePort}")


    def loop(self):
        self._running = True
        try:
            with self.socket:
                self.logger.info(f"Connected with {self.destinationNodePort}")

                self.txQueue.put(Message.nameRequest())
                if self.destinationNodePort == 0:
                    self.txQueue.put(Message.portRequest())

                while self._running:
                    self._receiveMessage()
                    self._sendMessage()
        except:
            self.closeConnection()
            raise

    def _sendMessage(self):
        if not self.txQueue.isEmpty():
            msg = self.txQueue.pop()
            self.logger.info(f"SEND({self.destinationNodePort}): {msg.control.name}")
            self.logger.debug(f"tx: {msg.toBytes().hex()}")
            self.socket.sendall(msg.toBytes())

    def _receiveMessage(self):
        completeData = b''
        while True and self._running:  # receive complete message
            if not self.txQueue.isEmpty():
                break

            try:
                data = self.socket.recv(1024)
                if not data:
                    self.closeConnection()
                    return

                completeData += data
                if len(data) == 1024:  # full socket
                    continue

                parsedMessages = self._parseData(completeData)
                for msg in parsedMessages:
                    self._processData(msg)
                break
            except BlockingIOError:
                time.sleep(0.5)
            except ConnectionResetError:
                self.closeConnection()

    def _processData(self, msg: Message):
        if msg.type == Message.Type.BROADCAST:
            self.logger.debug("Received broadcast")
            self.node.broadcastMessage(msg)

        if msg.data == b"close":
            self.closeConnection()
            return

        self.logger.debug(f"rx: {msg.toBytes().hex()}")
        self.logger.info(f"RECV({self.destinationNodePort}): {msg.control.name}")

        if msg.control == Message.Control.BLOCKCHAIN_REQUEST:
            blockchain_bytes = self.node.returnBlockchainBytes()
            if blockchain_bytes == None:
                return
            response = Message.blockchainResponse(blockchain_bytes)
            self.txQueue.put(response)
            return

        if msg.control == Message.Control.BLOCKCHAIN_RESPONSE:
            with self._lock:
                self.response = msg.data
            return

        if msg.control == Message.Control.TRANSACTION_ANNOUNCEMENT:
            trans = Transaction.fromBytes(msg.data)
            self.node.newTransaction(trans)
            return

        if msg.control == Message.Control.BLOCK_ANNOUNCEMENT:
            block = Block.fromBytes(msg.data)
            self.node.receivedBlock(block)
            return

        if msg.control == Message.Control.PORT_REQUEST:
            response = Message.portResponse(self.node.socketServerPort)
            self.txQueue.put(response)
            return

        if msg.control == Message.Control.PORT_RESPONSE:
            self.destinationNodePort = int.from_bytes(msg.data[0:4])
            return

        if msg.control == Message.Control.NAME_REQUEST:
            response = Message.nameResponse(self.node.name)
            self.txQueue.put(response)
            return

        if msg.control == Message.Control.NAME_RESPONSE:
            self.destinationNodeName = msg.data.decode()
            return

        if msg.control == Message.Control.ECHO:
            self.txQueue.put(msg)

    def _parseData(self, data: bytes) -> list[Message]:
        startIndex = 0
        messages = []
        while True:
            messageStart = data.find(Message.Version.VERSION_ONE.to_bytes(), startIndex)
            if messageStart == -1:
                return messages

            try:
                msg = Message.fromBytes(data[messageStart:])
                messages.append(msg)
                startIndex += Message.HEADER_LENGTH + msg.dataLength
            except (UnicodeDecodeError, ValueError):
                logging.warning(f"Failed to parse data: {data.hex()}")
                startIndex += 1
            continue


# ------------- NODE (SOCKET SERVER) -------------

class Node:
    def __init__(self, name: str, peers: Optional[list[int]], pk:str):
        self.peers=peers #initial peers dont confuse with connections
        self.wallet_key=pk
        self.connections = dict[int, Connection]()
        self._connections_threads = dict[int, threading.Thread]()
        self.name = name
        self.socketServer = self.prepareSocketServer()
        self.socketServerPort = self.socketServer.getsockname()[1]
        self.logger = self.prepareLogger()
        self.webServer = HTTPServer(self, self.logger)
        self.broadcastedMessages = set[int]()
        self._connId = self.connectionIDGenerator()
        self._blockchain_condition = threading.Condition()
        self._connection_lock = threading.Lock()
        self._blockchain = None
        self.stop = threading.Event()

    def prepareBlockchain(self) -> Optional[Blockchain]:
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
        # iterate over connections id instead of connections_pool cause connections_pool may change during iteration
        connIds = list(self.connections.keys())
        for id in connIds:  # pull blockchain from all connections
            connection = self.connections.get(id, None)
            if connection:
                results.append(connection.askForBlockchain())
                


        # TODO: handle varying blockchains
        s = sys.getsizeof(self._blockchain)
        for r in results:
            if sys.getsizeof(r) > s: #return bigger chain or None
                return r
        return None

    def returnBlockchainBytes(self) -> bytes:
        if self._blockchain == None:
            return
        with self._blockchain_condition:
            return self._blockchain.toBytes()

    def returnBlockchainObj(self) -> Blockchain:
        with self._blockchain_condition:
            result = deepcopy(self._blockchain)
        return result

    def returnAwaitingTransactions(self):
        with self._blockchain_condition:
            transactions = deepcopy(self._blockchain.pending_transactions)
        return transactions

    def prepareLogger(self):
        logger = logging.getLogger()
        logger.setLevel(logging.DEBUG)

        formatter = logging.Formatter("%(levelname)s:\t%(asctime)s - %(message)s", datefmt="%H:%M:%S")

        consoleHandler = logging.StreamHandler()
        consoleHandler.setFormatter(formatter)
        consoleHandler.setLevel(logging.INFO)

        logFilename = f"server_{self.name}_{str(self.socketServerPort)}.log"
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
        with self._blockchain_condition:
            try:
                if self._blockchain.add_transaction(transaction):
                    self._blockchain_condition.notify()
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
            for id, connection in self.connections.items():
                if connection.destination == msg.sender:  # Skip sending back to the origin peer TODO
                    continue
                self.logger.debug(f"Forward msg to conn id: {id} ({connection.destination})")
                connection.sendMessage(msg)
        else:
            self.logger.debug("Ignoring broadcast, message already handled")

    def connectionIDGenerator(self):
        connId = 1
        while True:
            yield connId
            connId += 1

    def removeConnection(self, conn: Connection):
        with self._connection_lock:
            self.connections.pop(conn.id)
            # TODO: improve removing connections so that the main thread can join each connection thread
            self._connections_threads.pop(conn.id)

    def newConnection(self, connectionSocket: socket.socket, addr, port: int = 0):
        id = next(self._connId)
        connection = Connection(connectionSocket, addr, id, self, port)
        connThread = threading.Thread(target=connection.loop)
        connThread.start()
        with self._connection_lock:
            self.connections[id] = connection
            self._connections_threads[id] = connThread

    def connect(self, ports: list[int]):
        for port in ports:
            try:
                cli = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                address = ("localhost", port)
                cli.connect(address)
                self.newConnection(cli, address, port)
            except ConnectionRefusedError:
                self.logger.info(f"Couldn't connect with {address}")

    def runSocketServer(self):
        def listenForConnections():
            self.logger.info(f"Start socket server {self.name} on port: {self.socketServerPort}")
            with self.socketServer as s:
                s.settimeout(1)
                while True and not self.stop.is_set():  # wait for connections, some sane upper limit can be applied
                    try:
                        conn, addr = s.accept()
                        self.newConnection(conn, addr)
                    except TimeoutError:
                        pass
                self.logger.info("Socket server stopped")

        self.socketServerThread = threading.Thread(target=listenForConnections)
        self.socketServerThread.start()

    def runWebServer(self):
        self.webServer.addAppRoutes()
        self.webServer.run()

    def minerLoop(self):
        assert self._blockchain is not None
        while True and not self.stop.is_set():
            with self._blockchain_condition:
                if self._blockchain.max_transactions_per_block():
                    if self._blockchain.mine_block_on_blockchain():
                        msg = Message.blockAnnouncement(self._blockchain.get_latest_block().toBytes())
                        self.broadcastMessage(msg)
                else:
                    self._blockchain_condition.wait(1)
        self.logger.info("Miner stopped")

    def runMiner(self):
        self.minerThread = threading.Thread(target=self.minerLoop)
        self.minerThread.start()


    def stopNode(self):
        self.logger.info("Stopping node")
        self.stop.set()
        self.minerThread.join(1)
        self.socketServerThread.join(1)

        if self._connections_threads:
            activeConnectionsCount = len(self._connections_threads.items())
            self.logger.warning(f"Connections still connected: {activeConnectionsCount}")
            assert threading.active_count() - 1 == activeConnectionsCount
            assert len(self.connections.items()) == activeConnectionsCount

        connIds = list(self.connections.keys())
        for id in connIds:
            conn = self.connections.get(id, None)
            if conn:
                conn.closeConnection()

        self.logger.info("Node stopped")

    #if miner wallet key is empty, run node in relay mode
    #relay mode: collect blockchain from peers, dont try to add transactions, broadcast incoming transactions
    #miner mode: add transactions to blockchain
    def run(self):
        if self.peers: #first create connections to peers
            self.connect(self.peers)
        self._blockchain = self.prepareBlockchain()
        if self.wallet_key != "":
            if not self._blockchain:
                # TODO: retry retrieving blockchain
                self.logger.warning("Node couldn't retrieve blockchain from peers, terminating")
                return
            self.runMiner()
        self.runSocketServer()
        self.runWebServer()

        # web server exited - terminate application
        self.stopNode()


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
