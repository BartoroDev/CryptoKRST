from multiprocessing import Process, Pipe
from fastapi import FastAPI
from pydantic import BaseModel
from py2p import mesh, base
import uvicorn

class Transaction(BaseModel):
    signature: str
    signer_public_key: str
    value: str

# Function to run the FastAPI app
def run_fastapi(conn):
    app = FastAPI()

    @app.post("/transaction")
    async def add_transaction(transaction: Transaction):
    # Send transaction data to the P2P process via the Pipe
        conn.send(transaction.signature.encode("utf-8")) #TODO:send full transaction
        return {"recieved signature":transaction.signature}

    uvicorn.run(app, host="127.0.0.1", port=8000)

# Function to run the P2P mesh network process
def run_p2p_network(conn):
    p2p_net = mesh.MeshSocket('localhost', 4444) #create open socket
    if(0>1): #TODO: make it connect to other peers
        p2p_net.connect("0.0.0.0",4445)

    while True:
        # Receive transaction data from the FastAPI process
        if conn.poll():  # Check if there is data in the pipe
            transaction = conn.recv()  # Receive the data
            p2p_net.send('this is', 'a test') #TODO: implement broadcasting logic of a transaction
            print(f"Received transaction: {transaction}")
            # Here, you would broadcast the transaction to the P2P network

if __name__ == "__main__":
    # Create a Pipe for communication between the processes
    parent_conn, child_conn = Pipe()
    # Create separate processes for FastAPI and P2P network
    fastapi_process = Process(target=run_fastapi, args=(parent_conn,))
    p2p_process = Process(target=run_p2p_network, args=(child_conn,))
    fastapi_process.start()
    p2p_process.start()

    # Wait for both processes to finish
    fastapi_process.join()
    p2p_process.join()
