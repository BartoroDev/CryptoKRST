import os
import time
import threading
import socket
import logging

class Message:
    def __init__(self, msg: str, source, destination = None):
        self.msg = msg
        self.source = source
        self.destination = destination


class ConnectionManager:                
    class Connection:
        def __init__(self, connection, destination, id, connManager: 'ConnectionManager'):
            self.connection = connection
            self.destination = destination
            self.id = id
            self.msgCount = 0
            self.connectionManager: ConnectionManager = connManager
            self.logger = connManager.logger

        def handle(self):
            data = None
            with self.connection:
                self.logger.info(f"Connected with {self.destination}")
                while data != "close": # loop through all data
                    data = self.connection.recv(1024)
                    if not data:
                        break
                    self.logger.info(f"RECV ({self.destination[1]}): {data}")
                    self.connection.sendall(data)

        def sendMessage(self):
            pass

    def __init__(self, name: str | None = None):
        self.connections = dict()
        self._connID = 1
        self.name = "1" if name == None else name
        self.server = self.prepareServer()
        self.port = self.server.getsockname()[1]
        self.logger = self.prepareLogger()


    def prepareServer(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind(("localhost", 0))
        server.listen()
        return server

    def sendToAll(self, msg: Message):
        for connection in self.connections:
            connection.sendMessage(msg)

    def removeConnection(self, conn: Connection):
        self.connections.pop(conn.id)

    def getConnectionID(self):
        yield self._connID
        self._connID += 1

    def prepareLogger(self):
        logger = logging.getLogger(__name__)
        name = f"server_{self.name}_{str(self.port)}.log"
        logging.basicConfig(filename=name, encoding='utf-8', level=logging.DEBUG, format='%(asctime)s %(message)s', datefmt='%m/%d/%Y %I:%M:%S')
        return logger

    def handleConnection(self, conn: socket.socket, addr):
        id = self.getConnectionID()
        connection = self.Connection(conn, addr, id, self)
        self.connections[id] = connection
        connThread = threading.Thread(target=connection.handle)
        connThread.start()

    def listenForConnections(self):
        self.logger.info(f"Start listening on port: {self.port}")
        with self.server as s:
            while True: # wait for connections, some sane upper limit can be applied
                conn, addr = s.accept()
                self.handleConnection(conn, addr)


def main():
    mgr = ConnectionManager()
    mgr.listenForConnections()


if __name__ == "__main__":
    main()