import hashlib
import json
import time
from ecdsa import SigningKey, VerifyingKey, SECP256k1, BadSignatureError
from typing import List, Union, Optional
from copy import deepcopy

from pydantic import BaseModel


# Constants
DIFFICULTY = "0000"
TRANSACTIONS_PER_BLOCK = 2

def sha256(data):
    return hashlib.sha256(data.encode()).hexdigest()


class Transaction:
    class Model(BaseModel):
        sender: str
        recipient: str
        amount: int
        timestamp:int
        signature:str
        hash:str

    """Represents a blockchain transaction."""
    def __init__(self, sender, recipient, amount):
        self.sender = sender        # Public key of the sender
        self.recipient = recipient  # Public key of the recipient
        self.amount = amount        # Amount to be transferred
        self.timestamp = round(time.time())
        self.signature = None       # Signature will be added later
        self.hash = self.generate_hash()

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
        if self.sender=="system" and self.amount==int(100/len(DIFFICULTY)):
            return True
        if not self.signature:
            raise ValueError("Transaction is not signed.")
        if not self.sender:
            raise ValueError("Sender public key is missing.")

        try:
            vk = VerifyingKey.from_string(bytes.fromhex(self.sender), curve=SECP256k1)
            result = vk.verify(bytes.fromhex(self.signature), self.hash.encode())
            return result
        
        except BadSignatureError:
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

    def mine_block(self, bc: "Blockchain"):
        """Mine the block by finding a hash that starts with the target difficulty."""
        bc.mining_active = True
        while not self.hash.startswith(DIFFICULTY) and bc.mining_active:
            self.nonce += 1
            self.hash = self.generate_hash()
        if self.hash.startswith(DIFFICULTY):
            print(f"Block mined: {self.hash}")
            return True
        else:
            return False

    def verify_transactions(self, miner_address):
        reward_transaction_count = 0  # Counter for reward transactions

        for transaction in self.transactions:
            if transaction.sender == "system" and transaction.recipient == miner_address:
                reward_transaction_count += 1
                # Reject block if multiple reward transactions are found
                if reward_transaction_count > 1:
                    print("Invalid block: Multiple miner reward transactions detected.")
                    return False
            else:
                # Verify signature for non-reward transactions
                if not transaction.verify_signature():
                    print("Invalid transaction: Signature verification failed.")
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
    def __init__(self,miners_address, blocks: Optional[list[Block]] = None):
        self.chain = [self.create_genesis_block()] if not blocks else blocks
        self.pending_transactions: List[Transaction] = []
        self.miners_address=miners_address

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
        genesis_block.nonce = 0

        while not genesis_block.hash.startswith(DIFFICULTY):
            genesis_block.nonce += 1
            genesis_block.hash = genesis_block.generate_hash()

        return genesis_block

    def get_latest_block(self):
        return self.chain[-1]

    def max_transactions_per_block(self):
        if len(self.pending_transactions) < TRANSACTIONS_PER_BLOCK:
            return False
        else:
            return True

    def add_transaction(self, transaction:Transaction):
        """Add a new transaction to the list of pending transactions after verification"""
        if self.verify_transaction(transaction):
            self.pending_transactions.append(transaction)
            return True
        else:
            print("Transaction invalid. Transaction rejected.")
            return False
    
    def verify_transaction(self, transaction:Transaction) -> bool:
        if transaction.sender == "system":
            return True  # Skip verification for reward transactions

        if not transaction.verify_signature():
            print("Transaction verification failed: Invalid signature.")
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
            print(f"Transaction verification failed: Insufficient balance {sender_balance}. ammount {transaction.amount}")
            return False

        # Step 3: Check for double spending
        for t in self.pending_transactions:
            if t.hash == transaction.hash:
                print("Transaction verification failed: Double spending detected.")
                return False

        print("Transaction verified successfully.")
        return True

    def append_block(self, block: Block, verify: bool = True):
        if verify:
            # TODO: this should be done when recieving a block 
            result = block.verify_transactions(self.miners_address)
        else:
            result = True
            
        if result:
            block.verify_transactions(self.miners_address)
            self.chain.append(block)
            self.pending_transactions = []
            return True
        else:
            print("Block contains invalid transactions")
            return False

    def mine_block_on_blockchain(self):
        """Mine the pending transactions and reward the miner."""

        # Create a new block with all pending transactions
        self.pending_transactions.append(Transaction(sender="system", recipient=self.miners_address, amount=int(100/len(DIFFICULTY))))
        new_block = Block(len(self.chain), self.get_latest_block().hash, self.pending_transactions)
        block_mined = new_block.mine_block(self)
        
        # Add the block to the chain and reset pending transactions
        if block_mined:
            self.append_block(new_block)
            self.display_chain()
        else:
            print("Block mining failed.")
        self.mining_active = False

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
            if not current_block.verify_transactions(self.miners_address):
                return False

        return True


    def try_add_block(self, block: Block) -> bool:
        if block.previous_hash == self.get_latest_block().hash:
            if not self.mining_active:
                print("Miners not mining!")
                return False

            for transaction in block.transactions:
                if transaction not in self.pending_transactions:
                    print(f"Transaction in proposed block not recognized!\n{transaction}")
                    return False

            self.interrupt_mining()
            return self.append_block(block, False)
        else:
            print("Received invalid block")
            return False

    def block_count(self):
        return len(self.chain)

    def get_block(self, block_no: int) -> Optional[Block]:
        if block_no < 0 or block_no >= self.block_count():
            print(f"Block number invalid! [{block_no}/{self.block_count()}]")
            return None

        return deepcopy(self.chain[block_no])

    def display_chain(self):
        """Display the entire blockchain."""
        for block in self.chain:
            print(f"Block {block.index}:")
            print(f"  Timestamp: {block.timestamp}")
            print(f"  Transactions: {[tx.as_dict() for tx in block.transactions]}")
            print(f"  Hash: {block.hash}")
            print(f"  Previous Hash: {block.previous_hash}")
            print(f"  Nonce: {block.nonce}\n")

    def as_dict(self):
        """Return a dictionary representation of the transaction."""
        return {
            "chain": [x.as_dict() for x in self.chain],
        }

    def __str__(self):
        return json.dumps(self.as_dict(), indent=4)

    def toBytes(self) -> bytes:
        return str(self).encode()

    @classmethod
    def fromBytes(cls, miners_address, data: bytes):
        jsonDict = json.loads(data)
        blocks = [Block.fromBytes(x) for x in jsonDict["chain"]]
        return cls(miners_address, blocks)


# Example Usage
if __name__ == "__main__":
    pass
    """ # Generate keys for sender and recipient using your seed-based function
    miner_public_key = get_public_key_from_pk("7e01f59d8d4793e62ab05b9cd9c3689fb62cbfd86280f677faf41c40181ea2b7")

    recipient_public_key = get_public_key_from_pk("recipient_seed")

    # Print the generated keys for demonstration
    print(f"Sender Public Key: {miner_public_key}")
    print(f"Recipient Public Key: {recipient_public_key}")

    # Create a blockchain with miner
    blockchain = Blockchain(miner_public_key)
    print("Added block 0")
    blockchain.display_chain()
    blockchain.mine_block_on_blockchain()
    blockchain.display_chain()
    
    # Create a new transaction
    tx1 = Transaction(sender=miner_public_key, recipient=recipient_public_key, amount=10)
    signtx1=sign_data("my_secure_seed", tx1.hash)
    tx1.signature=signtx1
    # Add the transaction to the blockchain
    blockchain.add_transaction(tx1)

    # Mine the pending transactions
    print("Mining block...")
    blockchain.mine_block_on_blockchain()

    # Display the blockchain
    print("\nBlockchain validation:", blockchain.is_chain_valid())
    blockchain.display_chain()

    tx2 = Transaction(sender=miner_public_key, recipient=recipient_public_key, amount=100)
    signtx2=sign_data("my_secure_seed", tx2.hash)
    tx2.signature=signtx2
    # Add the transaction to the blockchain
    blockchain.add_transaction(tx2) #TODO: tu sie wypiernicza

    # Mine the pending transactions
    print("Mining block...")
    blockchain.mine_block_on_blockchain()

    # Display the blockchain
    print("\nBlockchain validation:", blockchain.is_chain_valid())
    blockchain.display_chain() """