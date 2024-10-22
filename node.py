import argparse
import logging
import signal
from daemonize import Daemonize
from datetime import datetime


def parseArgs() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--init", action="store_true")
    return parser.parse_args()

class Node:
    def __init__(self, config: argparse.Namespace):
        self.config = config
        self.address = "127.0.0.1"
        self.port = 5454
        self.name = f"node_{self.port}"
        self.pid = f"/tmp/{self.name}.pid"
        self.logger, fileHandler = self.prepareLogger()
        self.log_fd = fileHandler.stream.fileno()

    def prepareLogger(self) -> tuple[logging.Logger, logging.FileHandler]:
        logger = logging.getLogger(__name__)
        logger.setLevel(logging.DEBUG)
        logger.propagate = False
        fh = logging.FileHandler(f"/tmp/{self.name}.log", "w")
        fh.setLevel(logging.DEBUG)
        logger.addHandler(fh)
        return (logger, fh)

    def finish(self):
        self.logger.warning(f"Miner {self.name} finished working at {datetime.now()}")

    def handleSIGTERM(self, signum, frame):
        self.finish()

    def start(self):
        signal.signal(signal.SIGTERM, self.handleSIGTERM)
        self.logger.info(f"Miner {self.name} started at {datetime.now()}")
        self.logger.debug(f"init config: {self.config.init}")
        self.finish()


if __name__ == "__main__":
    config = parseArgs()
    node = Node(config)
    daemon = Daemonize(app=node.name, pid=node.pid, action=node.start, keep_fds=[node.log_fd])
    daemon.start()