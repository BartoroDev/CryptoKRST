from pathlib import Path
from threading import Event
import hashlib
import json
import time
import logging
from threading import Event
from ecdsa import SigningKey, VerifyingKey, SECP256k1, BadSignatureError
from typing import List, Union, Optional
from copy import deepcopy

from pydantic import BaseModel


def sha256(data):
    return hashlib.sha256(data.encode()).hexdigest()


class Transaction:
    class Model(BaseModel):
        sender: str
        recipient: str
        amount: int
        timestamp: int
        signature: str
        hash: str

    """Represents a blockchain transaction."""
    def __init__(self, sender, recipient, amount):
        self.sender = sender        # Public key of the sender
        self.recipient = recipient  # Public key of the recipient
        self.amount = amount        # Amount to be transferred
        self.timestamp = int(time.time())
        self.signature = None       # Signature will be added later
        self.hash = self.generate_hash()

    @classmethod
    def fromModel(cls, model: Model):
        tx = cls(model.sender, model.recipient, model.amount)
        tx.timestamp = model.timestamp
        tx.signature = model.signature
        tx.hash = model.hash
        return tx

    def generate_hash(self):
        """Generate a unique hash for the transaction."""
        transaction_content = f"{self.sender}{self.recipient}{self.amount}{self.timestamp}"
        return sha256(transaction_content)

    def sign_transaction(self, private_key):
        """Sign the transaction using the sender's private key."""
        if not self.sender:
            raise ValueError("Sender public key is required to sign a transaction.")
        
        # Generate a signature using the private key
        sk = SigningKey.from_string(bytes.fromhex(private_key), curve=SECP256k1)
        self.signature = sk.sign(self.hash.encode()).hex()

    def verify_signature(self):
        """Verify the transaction's signature using the sender's public key."""
        if self.sender=="system": # and self.amount==int(100/len(DIFFICULTY)):
            return True
        try:
            if not self.signature:
                raise ValueError("Transaction is not signed.")
            if not self.sender:
                raise ValueError("Sender public key is missing.")

            vk = VerifyingKey.from_string(bytes.fromhex(self.sender), curve=SECP256k1)
            result = vk.verify(bytes.fromhex(self.signature), self.hash.encode())
            return result
        
        except (ValueError, BadSignatureError):
            return False

    def as_dict(self):
        """Return a dictionary representation of the transaction."""
        return {
            "sender": self.sender,
            "recipient": self.recipient,
            "amount": self.amount,
            "timestamp": self.timestamp,
            "signature": self.signature,
            "hash": self.hash
        }

    def toBytes(self) -> bytes:
        return str(self).encode()

    @classmethod
    def fromBytes(cls, data: Union[bytes, dict]):
        if isinstance(data, dict):
            jsonDict = data
        else:
            jsonDict = json.loads(data)

        transaction = cls(jsonDict["sender"], jsonDict["recipient"], jsonDict["amount"])
        transaction.timestamp = jsonDict["timestamp"]
        transaction.signature = jsonDict["signature"]
        transaction.hash = jsonDict["hash"]
        return transaction

    def __str__(self):
        return json.dumps(self.as_dict(), indent=4)

    def __eq__(self, other: object) -> bool:
        if isinstance(other, Transaction):
            if self.sender != other.sender:
                return False
            if self.recipient != other.recipient:
                return False
            if self.amount != other.amount:
                return False
            if self.timestamp != other.timestamp:
                return False
            if self.signature != other.signature:
                return False
            if self.hash != other.hash:
                return False
            return True
        return False

class Block:
    def __init__(self, index, previous_hash, transactions: List[Transaction]):
        self.index = index
        self.previous_hash = previous_hash
        self.transactions = transactions
        self.timestamp = time.time()
        self.nonce = 0
        self.hash = self.generate_hash()

    def generate_hash(self):
        """Generate a SHA-256 hash of the block."""
        transactions_data = json.dumps([tx.as_dict() for tx in self.transactions], sort_keys=True)
        block_content = f"{self.index}{self.previous_hash}{transactions_data}{self.timestamp}{self.nonce}"
        return sha256(block_content)

    def mine_block(self, bc: "Blockchain", stopEvent: Event):
        """Mine the block by finding a hash that starts with the target difficulty."""
        bc.mining_active = True
        for _ in range(2):
            self.hash = "0"
            while not self.hash.startswith(bc.difficulty) and bc.mining_active and not stopEvent.is_set():
                self.nonce += 1
                self.hash = self.generate_hash()

        if self.hash.startswith(bc.difficulty) and bc.mining_active:
            return True
        else:
            return False

    def verify_transactions(self):
        reward_transaction_count = 0  # Counter for reward transactions

        for transaction in self.transactions:
            if transaction.sender == "system":
                reward_transaction_count += 1
                # Reject block if multiple reward transactions are found
                if reward_transaction_count > 1:
                    return False
            else:
                # Verify signature for non-reward transactions
                if not transaction.verify_signature():
                    return False

        return True

    def as_dict(self):
        """Return a dictionary representation of the transaction."""
        return {
            "index": self.index,
            "previous_hash": self.previous_hash,
            "transactions": [x.as_dict() for x in self.transactions],
            "timestamp": self.timestamp,
            "nonce": self.nonce,
            "hash": self.hash
        }

    def toBytes(self) -> bytes:
        return str(self).encode()

    @classmethod
    def fromBytes(cls, data: Union[bytes, dict]):
        if isinstance(data, dict):
            jsonDict = data
        else:
            jsonDict = json.loads(data)

        transactions = [Transaction.fromBytes(x) for x in jsonDict["transactions"]]
        block = cls(jsonDict["index"], jsonDict["previous_hash"], transactions)
        block.timestamp = jsonDict["timestamp"]
        block.nonce = jsonDict["nonce"]
        block.hash = jsonDict["hash"]
        return block

    def __str__(self):
        return json.dumps(self.as_dict(), indent=4)

    def __eq__(self, other: object) -> bool:
        if isinstance(other, Block):
            if self.index != other.index:
                return False
            if self.previous_hash != other.previous_hash:
                return False
            if self.timestamp != other.timestamp:
                return False
            if self.nonce != other.nonce:
                return False
            if self.hash != other.hash:
                return False
            if len(self.transactions) != len(other.transactions):
                return False
            for this_tx, other_tx in zip(self.transactions, other.transactions):
                if this_tx != other_tx:
                    return False
            return True
        return False



class Blockchain:
    def __init__(self,miners_address, difficulty_level: int, blocks: Optional[list[Block]] = None, logger: Optional[logging.Logger]=None):
        self.difficulty = difficulty_level * "0"
        self.chain = [self.create_genesis_block()] if not blocks else blocks
        self.pending_transactions: List[Transaction] = []
        self.miners_address=miners_address
        self.logger = logger if logger else logging.getLogger(__name__)

    def create_genesis_block(self): 
        coinbase_message = "Mon Dec 16 2024 21:00:00 GMT+0000"
        reward = 2000000

        coinbase_transaction = Transaction("COINBASE", "system", reward)
        coinbase_transaction.signature = coinbase_message  
        coinbase_transaction.timestamp = 1734382800  # same as in message
        coinbase_transaction.hash=coinbase_transaction.generate_hash()
        transactions = [coinbase_transaction]

        genesis_block = Block(0, "0000", transactions)
        genesis_block.timestamp = 1734382800  # same as in message
        genesis_block.nonce = 42485890

        genesis_block.hash = genesis_block.generate_hash()
        assert genesis_block.hash.startswith("000000")

        return genesis_block

    def get_latest_block(self):
        return self.chain[-1]

    def add_transaction(self, transaction:Transaction):
        """Add a new transaction to the list of pending transactions after verification"""
        if self.verify_transaction(transaction):
            self.pending_transactions.append(transaction)
            return True
        else:
            self.logger.info("Transaction invalid. Transaction rejected.")
            return False
    
    def verify_transaction(self, transaction:Transaction) -> bool:
        if transaction.sender == "system":
            return True  # Skip verification for reward transactions

        if not transaction.verify_signature():
            self.logger.info("Transaction verification failed: Invalid signature.")
            return False

        # Step 2: Check sender balance
        sender_balance = 0
        for block in self.chain:
            for t in block.transactions:
                if t.recipient == transaction.sender:
                    sender_balance += t.amount  # Add received amount
                if t.sender == transaction.sender:
                    sender_balance -= t.amount  # Subtract sent amount

        for t in self.pending_transactions:  # Include pending transactions
            if t.recipient == transaction.sender:
                sender_balance += t.amount
            if t.sender == transaction.sender:
                sender_balance -= t.amount

        if sender_balance < transaction.amount:
            self.logger.warning(f"Transaction verification failed: Insufficient balance {sender_balance}. ammount {transaction.amount}")
            return False

        # Step 3: Check for double spending
        for t in self.pending_transactions:
            if t.hash == transaction.hash:
                self.logger.warning("Transaction verification failed: Double spending detected.")
                return False

        self.logger.info("Transaction verified successfully.")
        return True

    def append_block(self, block: Block):
        self.chain.append(block)
        for tx in block.transactions:
            try:
                self.pending_transactions.remove(tx)
            except ValueError:
                if tx.sender != "system":
                    self.logger.info(f"Transaction {tx} not recognized in transaction pool")
                continue

        self.logger.info(f"Block: {block.index} added to chain")
        return True


    def mine_block_on_blockchain(self, stopEvent: Event) -> bool:
        """Mine the pending transactions and reward the miner."""

        # Create a new block with all pending transactions
        transactions_in_block = deepcopy(self.pending_transactions)
        transactions_in_block.append(Transaction(sender="system", recipient=self.miners_address, amount=10))
        new_block = Block(self.block_count(), self.get_latest_block().hash, transactions_in_block)
        block_mined = new_block.mine_block(self, stopEvent)
        
        # Add the block to the chain and reset pending transactions
        self.mining_active = False
        if block_mined:
            self.logger.info(f"Block: {new_block.index} mined successfully")
            self.append_block(new_block)
            return True
        else:
            return False

    def interrupt_mining(self):
        self.mining_active = False

    def to_json(self):
        return json.dumps(self.chain)

    def verify_chain(self):
        """Validate the entire blockchain."""
        if self.chain[0] != self.create_genesis_block():
            return False

        for i in range(1, len(self.chain)):
            current_block = self.chain[i]
            previous_block = self.chain[i - 1]

            # Validate current block's hash
            if current_block.hash != current_block.generate_hash():
                return False

            # Validate previous hash link
            if current_block.previous_hash != previous_block.hash:
                return False

            # Validate transactions
            if not current_block.verify_transactions():
                return False

        return True

    def check_recv_block_hash(self, block: Block) -> bool:
        if not block.hash.startswith(self.difficulty):
            return False
        else:
            temp_hash = block.hash
            if block.generate_hash() != temp_hash:
                return False
            else:
                return True

    def try_add_block(self, block: Block) -> bool:
        if not self.check_recv_block_hash(block):
            return False

        if not block.verify_transactions():
            return False

        last_block = self.get_latest_block()
        if block == last_block:
            return False

        if block.previous_hash == last_block.hash:
            if not self.mining_active:
                self.logger.warning("Miners not mining!")
                return False

            self.interrupt_mining()
            return self.append_block(block)
        else:
            return False

    def block_count(self):
        return len(self.chain)

    def get_block(self, block_no: int) -> Optional[Block]:
        if block_no < 0 or block_no >= self.block_count():
            self.logger.warning(f"Block number invalid! [{block_no}/{self.block_count()}]")
            return None

        return deepcopy(self.chain[block_no])

    def as_dict(self):
        """Return a dictionary representation of the transaction."""
        return {
            "chain": [x.as_dict() for x in self.chain],
        }

    def toBytes(self) -> bytes:
        return str(self).encode()

    @classmethod
    def fromBytes(cls, miners_address, difficulty_level, data: bytes, logger: logging.Logger):
        jsonDict = json.loads(data)
        blocks = [Block.fromBytes(x) for x in jsonDict["chain"]]
        return cls(miners_address, difficulty_level, blocks, logger)

    def __str__(self):
        return json.dumps(self.as_dict(), indent=4)

    def __eq__(self, other: object) -> bool:
        if isinstance(other, Blockchain):
            if self.block_count() != other.block_count():
                return False
            for block_no in range(self.block_count()):
                b_s = self.get_block(block_no)
                b_o = other.get_block(block_no)
                if b_s != b_o:
                    return False
            return True
        return False

def createInvalidBlock():
    with Path("config.json").open() as c:
        blocks = []
        config = json.load(c)
        pub_key_A = config["A"]["publicKey"]
        pub_key_B = config["B"]["publicKey"]
        bc = Blockchain(pub_key_A, 5)
        tx1 = Transaction(pub_key_A, pub_key_B, 1000000)
        b = Block(31, "00000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", [tx1])
        blocks.append(b.as_dict())
        b.mine_block(bc, Event())
        blocks.append(b.as_dict())
        b.hash = b.hash.replace("0", "1")
        blocks.append(b.as_dict())
        with Path("malicious_block.json").open("w") as mb:
            json.dump(blocks, mb)

if __name__ == "__main__":
    createInvalidBlock()