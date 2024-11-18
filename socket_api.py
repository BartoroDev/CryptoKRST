import socket
import argparse
import time
from multiprocessing import Process, Queue
from node import Message, Node
from fastapi import FastAPI
from pydantic import BaseModel
from py2p import mesh, base
import uvicorn
import random;

HOST = "localhost"

class Transaction(BaseModel):
    signature: str
    signer_public_key: str
    value: str

def parseArgs() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    #parser.add_argument('--node', action=argparse.BooleanOptionalAction) #start another node automatically
    parser.add_argument("--name", default="A", type=str)
    parser.add_argument("--join", nargs="*", type=int)

    args = parser.parse_args()
    return args

def run_fastapi_queue(q:Queue):
    app = FastAPI()
    p = random.randint(8000, 8999)
    print(f"rest api on port {p}")

    @app.post("/transaction")
    async def add_transaction(transaction: Transaction):
    # Send transaction data to the P2P process via the Pipe
        q.put(transaction.signature.encode("utf-8")) #TODO:send full transaction
        return {"recieved signature":transaction.signature}

    uvicorn.run(app, host="127.0.0.1", port=p)

def init(q, joinport, name):
    node = Node(name)
    if joinport:
        node.connect(joinport)
    q.put(node.server.getsockname()[1])
    node.listenForConnections()

def main(port, api_queue):
    msgId = 1
    msg = Message.fromData(b"Connected", Message.Version.VERSION_ONE, Message.Type.UNICAST, msgId)
    inputed = None
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect(("localhost", port))
        while True:
            if api_queue.empty():
                time.sleep(1)
                continue
            inputed = "b!"+str(api_queue.get())
                
            bmsg = msg.toBytes()
            s.sendall(bmsg)
            received = s.recv(1024)
            print(f"({s.getpeername()[1]})S: {received!r}")

            msgId += 1
            msgType = Message.Type.BROADCAST if inputed[:2] == "b!" else Message.Type.UNICAST
            msg = Message.fromData(inputed.encode(), Message.Version.VERSION_ONE, msgType, msgId)


if __name__ == "__main__":
    q = Queue()
    i = Queue()
    pargs = parseArgs()

    p = Process(target=init, args=(i,pargs.join,pargs.name))#init node
    p.start()
    time.sleep(4)
    port = i.get()
    print(f"Node on port {port}")

    api = Process(target=run_fastapi_queue, args=(q,))
    api.start()
    main(port,q)#connect api to node (message pusher)