import json
import time
from pathlib import Path
import socket
import argparse

from pow import Block
from node import Message

HOST = "localhost"

def parseArgs() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("port", type=int)
    parser.add_argument("--data-file", type=Path)
    args = parser.parse_args()
    return args

def prepareBlocks(file: Path):
    with file.open() as f:
        blocks_data = json.load(f, object_hook=lambda d: dict(**d))
        blocks = []
        for block in blocks_data:
            blocks.append(Block.fromBytes(block))
        return blocks


def main(args):
    msgId = 1
    msg = Message("Connected", 0)
    inputed = None
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect(("localhost", args.port))
        clientPort = s.getsockname()[1]

        if args.data_file and Path(args.data_file).exists():
            blocks = prepareBlocks(Path(args.data_file))
            for id, block in enumerate(blocks):
                s.sendall(Message.blockAnnouncement(clientPort, block.toBytes()).toBytes())
                print(f"Block {id} sent")
                time.sleep(0.1)
            return

        s.settimeout(1)
        while True:
            bmsg = msg.toBytes()
            s.sendall(bmsg)
            if inputed == "close":
                break

            try:
                received = s.recv(1024)
                print(f"({s.getpeername()[1]})S: {received!r}")
                receivedMsg = Message.fromBytes(received)

                if receivedMsg.control == Message.Control.NAME_REQUEST:
                    msg = Message.nameResponse(clientPort, "socket client")
                    continue
            except TimeoutError:
                pass

            inputed = input(f"({clientPort})C: ")
            msgId += 1
            msgType = Message.Type.BROADCAST if inputed[:2] == "b!" else Message.Type.UNICAST
            if msgType == Message.Type.BROADCAST:
                inputed = inputed[2:]
            msg = Message(inputed, clientPort, type=msgType)


if __name__ == "__main__":
    args = parseArgs()
    main(args)
