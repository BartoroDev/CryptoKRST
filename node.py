import time
import threading
import socket
import logging
import argparse
import json

from copy import deepcopy
from typing import Optional, Union
from enum import IntEnum, auto
from zlib import adler32
from pathlib import Path

from fastapi import FastAPI
import uvicorn

from pow import Transaction, Blockchain, Block
from wallet import get_public_key_from_pk

# ------------- PROTOCOL - MESSAGES IMPLEMENTATION -------------

DIFFICULTY_LEVEL = 5

class Message:
    # |VERSION(1b)|TYPE(1b)|CONTROL(1b)|SOURCE(4b)|HASH(4b)|DATA_LENGTH(2b)|DATA|
    HEADER_LENGTH=13
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
        NAME_REQUEST = 6
        NAME_RESPONSE = 7

    def __init__(self, data: Union[str, bytes], sourcePort: int, *, version: Version = Version.VERSION_ONE, type: Type = Type.UNICAST, control: Control = Control.ECHO, hash: int = 0):
        self.version = version
        self.type = type
        self.control = control
        if isinstance(data, str):
            self.data = data.encode()
        else:
            assert isinstance(data, bytes)
            self.data = data

        self.source = sourcePort
        self.hash = adler32(self.data + int(time.time()).to_bytes(4)) if not hash else hash
        self.dataLength = len(data)


    def toBytes(self) -> bytes:
        return self.version.to_bytes(1) + self.type.to_bytes(1) + self.control.to_bytes(1) + self.source.to_bytes(4) + self.hash.to_bytes(4) + self.dataLength.to_bytes(2) + self.data

    @classmethod
    def fromBytes(cls, msg: bytes):
        version = cls.Version.from_bytes(msg[0:1])
        type = cls.Type.from_bytes(msg[1:2])
        control = cls.Control.from_bytes(msg[2:3])
        source = int.from_bytes(msg[3:7])
        hash = int.from_bytes(msg[7:11])
        dataLength = int.from_bytes(msg[11:13])
        assert len(msg[13:]) >= dataLength, f"""
            HEADER:\t{msg[:13].hex()}
            DATA:\t{msg[13:].hex()}
            EXPECTED DATA_LEN:\t{dataLength}
            ACTUAL DATA_LEN:\t{len(msg[13:])}
            """
        if dataLength > 0:
            data = msg[13:(13+dataLength)]
        else:
            data = ""
        return cls(data, source, version=version, type=type, control=control, hash=hash)

    @classmethod
    def blockchainRequest(cls, source: int):
        return cls("", source, control=cls.Control.BLOCKCHAIN_REQUEST)

    @classmethod
    def blockchainResponse(cls, source: int, data):
        return cls(data, source, control=cls.Control.BLOCKCHAIN_RESPONSE)

    @classmethod
    def blockAnnouncement(cls, source: int, data):
        return cls(data, source, type=cls.Type.BROADCAST, control=cls.Control.BLOCK_ANNOUNCEMENT)

    @classmethod
    def transactionAnnouncement(cls, source: int, data):
        return cls(data, source, type=cls.Type.BROADCAST, control=cls.Control.TRANSACTION_ANNOUNCEMENT)

    @classmethod
    def nameRequest(cls, source: int):
        return cls("", source, control=cls.Control.NAME_REQUEST)

    @classmethod
    def nameResponse(cls, source: int, name: str):
        return cls(name, source, control=cls.Control.NAME_RESPONSE)


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
        if self.node.mode == NodeMode.FULL_MODE:
            # TODO: compere this node's chain with the fetched one and possibly update
            result = self.node.returnBlockchainObj()
        else:
            assert self.node.mode is NodeMode.RELAY_ONLY
            result = self.node.fetchBlockchainFromPeers()

        if result is None:
            return {}

        return result.as_dict()

    def get_connections(self):
        connections_dict = {
            "node name": self.node.name,
            "node port": self.node.socketServerPort,
            "connections": [connection.as_dict() for connection in self.node.connections.values()]
        }
        return connections_dict
    
    def get_public_key(self):
        if self.node.blockchain is None:
            return {}
        return {"public_key":str(get_public_key_from_pk(self.node.wallet_key))}

    def get_transactions(self):
        if self.node.mode is NodeMode.RELAY_ONLY:
            return {}

        assert self.node.blockchain is not None
        transactions = self.node.returnAwaitingTransactions()
        if not transactions:
            return {}

        return {str(id): tx.as_dict() for id, tx in enumerate(transactions)}

    def add_transaction(self, transaction: Transaction.Model):
        trans = Transaction.fromModel(transaction)
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
    def __init__(self, connection: socket.socket, id: int, sourcePort: int, node: "Node", serverPort = 0):
        self.socket = connection
        self.destinationNodePort = serverPort  # port on which the connected server listens for connections
        self.destinationNodeName = ""
        self.source = sourcePort
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
        request = Message.blockchainRequest(self.source)
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

                self.txQueue.put(Message.nameRequest(self.source))

                while self._running:
                    self._receiveMessage()
                    self._sendMessage()
        except:
            self.closeConnection()
            raise

    def _sendMessage(self):
        if not self.txQueue.isEmpty():
            msg = self.txQueue.pop()
            self.logger.debug(f"tx: {msg.toBytes().hex()}")
            self.logger.info(f"{self.source}-SEND({self.destinationNodePort}): {msg.control.name}")
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
        if msg.data == b"close":
            self.closeConnection()
            return

        if self.destinationNodePort == 0:
            self.destinationNodePort = msg.source

        self.logger.debug(f"rx: {msg.toBytes().hex()}")
        self.logger.info(f"{self.source}-RECV({self.destinationNodePort}): {msg.control.name}")

        if msg.control == Message.Control.BLOCKCHAIN_REQUEST:
            blockchain_bytes = self.node.returnBlockchainObj().toBytes()
            if blockchain_bytes == None:
                return
            response = Message.blockchainResponse(self.source, blockchain_bytes)
            self.txQueue.put(response)
            return

        if msg.control == Message.Control.BLOCKCHAIN_RESPONSE:
            with self._lock:
                self.response = msg.data
            return

        if msg.control == Message.Control.TRANSACTION_ANNOUNCEMENT:
            trans = Transaction.fromBytes(msg.data)
            self.node.newTransaction(trans, msg)
            return

        if msg.control == Message.Control.BLOCK_ANNOUNCEMENT:
            self.node.receivedBlock(msg)
            return

        if msg.control == Message.Control.NAME_REQUEST:
            response = Message.nameResponse(self.source, self.node.name)
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
                logging.warning(f"Failed to parse data: {data[messageStart:].hex()}")
                startIndex += 1
            continue


# ------------- NODE (SOCKET SERVER) -------------

#relay mode: collect blockchain from peers, broadcast incoming transactions
#full mode: relay_mode features + mine blocks
class NodeMode(IntEnum):
    RELAY_ONLY = auto()
    FULL_MODE = auto()

class Node:
    def __init__(self, name: str, peers: Optional[list[int]], pk: str, mode: NodeMode):
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
        self.blockchain = None
        self.stop = threading.Event()
        self.mode = mode

    def prepareBlockchain(self) -> bool:
        assert self.mode is NodeMode.FULL_MODE
        miner_public_key = get_public_key_from_pk(self.wallet_key)
        if len(self.connections.keys()) == 0:
            self.blockchain = Blockchain(miner_public_key, DIFFICULTY_LEVEL, logger=self.logger)
            self.logger.info("Node starts its own blockchain")
            return True
        else:
            blockchain = self.fetchBlockchainFromPeers()
            if not blockchain:
                # TODO: periodically retry retrieving blockchain
                self.logger.warning("Node couldn't retrieve blockchain from peers, miner's not activated")
                self.mode = NodeMode.RELAY_ONLY
                return False
            else:
                blockchain.miners_address = miner_public_key
                self.blockchain = blockchain
                return True

    def fetchBlockchainFromPeers(self) -> Optional[Blockchain]:
        # iterate over ids instead of connections cause connections may be added/removed during iteration
        chains = dict[int, Blockchain]()
        scores = dict[int, int]()
        connIds = list(self.connections.keys())
        for id in connIds:  # pull blockchain from all connections
            connection = self.connections.get(id, None)
            if connection:
                current_chain = connection.askForBlockchain()
                if not current_chain:
                    continue
                bc = Blockchain.fromBytes(None, DIFFICULTY_LEVEL, current_chain, self.logger)
                if not bc.verify_chain():
                    # TODO: mark connections as suspicious
                    continue
                chains[id] = bc 
                scores[id] = 0

        if not chains:
            self.logger.warning("Fetching blockchain from peers failed")
            return None

        # calculate blockchain length occurrences:
        unique_chain_sizes = dict[int, int]()  # {chain_size, amount of occurrences}
        for id, chain in chains.items():
            chain_size = chain.block_count()
            if chain_size in unique_chain_sizes.keys():
                unique_chain_sizes[chain_size] += 1
            else:
                unique_chain_sizes[chain_size] = 0

        # find best blockchain length:
        bestSizeCount = 0
        bestSizeValue = 0
        for value, count in unique_chain_sizes.items():
            if count > bestSizeCount:
                bestSizeCount = count
                bestSizeValue = value
                continue

            if count == bestSizeCount and value > bestSizeValue:
                # found chain with the same amount of occurrences but longer
                bestSizeValue = value
                bestSizeCount = count

        self.logger.info(f"Blockchain length {bestSizeValue} appeared {bestSizeCount} times")

        # drop blockchains of different lengths
        ids = list(chains.keys())
        for id in ids:
            chain_length = chains[id].block_count()
            if  chain_length != bestSizeValue:
                chains.pop(id)
                # TODO: mark connection as potentially fishy
                self.logger.warning(f"Received a blockchain of suspicious length [received: {chain_length}, expected: {bestSizeValue}] from connection: {id}")

        unique_blocks = list[Block]()

        for block_no in range(0, bestSizeValue):
            for id, chain in chains.items():
                block = chain.get_block(block_no)
                if not block:
                    continue
                if block not in unique_blocks:
                    unique_blocks.append(block)
            
            for id, chain in chains.items():
                block = chain.get_block(block_no)
                if block in unique_blocks:
                    scores[id] += 1

        best_chain = None
        best_score = 0
        competing_chains = 0
        for id, score in scores.items():
            if score > best_score:
                competing_chains += 1
                best_score = score
                best_chain = chains[id]

        self.logger.info(f"Chain chosen from {competing_chains}")

        return best_chain

    def returnBlockchainObj(self) -> Blockchain:
        assert self.blockchain != None
        result = deepcopy(self.blockchain)
        return result

    def returnAwaitingTransactions(self):
        assert self.blockchain != None
        transactions = deepcopy(self.blockchain.pending_transactions)
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

    def newTransaction(self, transaction: Transaction, msg: Optional[Message]=None) -> bool:
        msg = msg if msg else Message.transactionAnnouncement(self.socketServerPort, transaction.toBytes())
        self.broadcastMessage(msg)
        if self.mode is NodeMode.RELAY_ONLY:  # if not mining dont add transaction
            return True


        assert self.blockchain is not None
        if transaction in self.blockchain.pending_transactions:
            return False
        try:
            return self.blockchain.add_transaction(transaction)
        except ValueError:
            return False

    def receivedBlock(self, msg: Message):
        self.broadcastMessage(msg)
        if self.mode is NodeMode.RELAY_ONLY:
            return

        assert self.blockchain is not None
        block = Block.fromBytes(msg.data)
        if not self.blockchain.try_add_block(block):
            self.logger.info("Block invalid")

    def broadcastMessage(self, msg: Message):
        if msg.hash not in self.broadcastedMessages: 
            self.broadcastedMessages.add(msg.hash)
            for id, connection in self.connections.items():
                if connection.destinationNodePort == msg.source:
                    continue
                self.logger.debug(f"Broadcast msg {msg.control.name} to conn id: {id}")
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

    def newConnection(self, connectionSocket: socket.socket, destinationPort: int = 0):
        id = next(self._connId)
        connection = Connection(connectionSocket, id, self.socketServerPort, self, destinationPort)
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
                self.newConnection(cli, port)
            except ConnectionRefusedError:
                self.logger.info(f"Couldn't connect with {address}")

    def runSocketServer(self):
        def listenForConnections():
            self.logger.info(f"Start socket server {self.name} on port: {self.socketServerPort}")
            with self.socketServer as s:
                s.settimeout(1)
                while True and not self.stop.is_set():  # wait for connections, some sane upper limit can be applied
                    try:
                        conn, _ = s.accept()
                        self.newConnection(conn)
                    except TimeoutError:
                        pass
                self.logger.info("Socket server stopped")

        self.socketServerThread = threading.Thread(target=listenForConnections)
        self.socketServerThread.start()

    def runWebServer(self):
        self.webServer.addAppRoutes()
        self.webServer.run()

    def minerLoop(self):
        assert self.blockchain is not None
        while True and not self.stop.is_set():
            if self.blockchain.mine_block_on_blockchain(self.stop):
                msg = Message.blockAnnouncement(self.socketServerPort, self.blockchain.get_latest_block().toBytes())
                self.broadcastMessage(msg)

        self.logger.info("Miner stopped")

    def runMiner(self):
        self.minerThread = threading.Thread(target=self.minerLoop)
        self.minerThread.start()


    def stopNode(self):
        self.logger.info("Stopping node")
        self.stop.set()
        if self.mode is NodeMode.FULL_MODE and hasattr(self, "minerThread") :
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

    def run(self):
        if self.peers: #first create connections to peers
            self.connect(self.peers)
        if self.mode is NodeMode.FULL_MODE:
            if self.prepareBlockchain():
                self.runMiner()

        self.runSocketServer()
        self.runWebServer()

        # web server exited - terminate application
        self.stopNode()


def parseArgs() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--wallet-key", type=str)
    parser.add_argument("--mode", type=str, choices=["relay", "full"], default="full")
    parser.add_argument("--config-file", type=Path, default=Path("config.json"))
    parser.add_argument("--name", default="A", type=str)
    parser.add_argument("--join", nargs="*", type=int)
    return parser.parse_args()

def main():
    args = parseArgs()
    wallet_key = ""
    if args.wallet_key:
        wallet_key = args.wallet_key
    
    mode = NodeMode.FULL_MODE if args.mode == "full" else NodeMode.RELAY_ONLY

    if not wallet_key and mode is NodeMode.FULL_MODE:
        with args.config_file.open("r") as config_file:
            try:
                config = json.load(config_file)
                wallet_key = config[args.name]["privateKey"]
            except json.JSONDecodeError:
                print("There is no key matching provided name in the config file")
                return

    if mode is NodeMode.FULL_MODE:
        try:
            get_public_key_from_pk(wallet_key)
        except ValueError:
            print("Provided key is invalid")

    node = Node(args.name, args.join, wallet_key, mode)
    node.run()


if __name__ == "__main__":
    main()
