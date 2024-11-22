import hashlib
import json
import time
from ecdsa import SigningKey, VerifyingKey, SECP256k1, BadSignatureError
from typing import List

from wallet import get_public_key_from_seed, sign_data

# Constants
DIFFICULTY = "0000"

def sha256(data):
    return hashlib.sha256(data.encode()).hexdigest()


class Transaction:
    """Represents a blockchain transaction."""
    def __init__(self, sender, recipient, amount):
        self.sender = sender        # Public key of the sender
        self.recipient = recipient  # Public key of the recipient
        self.amount = amount        # Amount to be transferred
        self.timestamp = time.time()
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
        if self.sender=="system":
            return True
        if not self.signature:
            raise ValueError("Transaction is not signed.")
        if not self.sender:
            raise ValueError("Sender public key is missing.")
        
        
        try:
            vk = VerifyingKey.from_string(bytes.fromhex(self.sender), curve=SECP256k1)
            result = vk.verify(bytes.fromhex(self.signature['signature']), self.hash.encode())
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

    def __str__(self):
        return json.dumps(self.as_dict(), indent=4)


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

    def mine_block(self):
        """Mine the block by finding a hash that starts with the target difficulty."""
        while not self.hash.startswith(DIFFICULTY): 
            self.nonce += 1
            self.hash = self.generate_hash()
        print(f"Block mined: {self.hash}")

    def verify_transactions(self):
        reward_transaction_count = 0  # Counter for reward transactions

        for transaction in self.transactions:
            if transaction.sender == "system":
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


class Blockchain:
    def __init__(self,miners_address):
        self.chain = [self.create_genesis_block()]
        self.pending_transactions: List[Transaction] = []
        self.miners_address=miners_address

    def create_genesis_block(self): 
        """Create the first block (genesis block) in the chain."""
        return Block(0, "0", [Transaction("COINBASE", "system" , 2000000)])

    def get_latest_block(self):
        return self.chain[-1]

    def add_transaction(self, transaction:Transaction):
        """Add a new transaction to the list of pending transactions after verification"""
        if transaction.verify_signature() and self.is_ammount_valid(transaction):
            self.pending_transactions.append(transaction)
        else:
            print("Transaction invalid. Transaction rejected.")

    def mine_block_on_blockchain(self):
        """Mine the pending transactions and reward the miner."""
        #if not self.pending_transactions:
        #    print("No transactions to mine.")
        #    return

        # Reward transaction to the miner TODO:implement reward system
        # Create a new block with all pending transactions
        self.pending_transactions.append(Transaction(sender="system", recipient=self.miners_address, amount=100))
        new_block = Block(len(self.chain), self.get_latest_block().hash, self.pending_transactions)
        new_block.mine_block()

        # Add the block to the chain and reset pending transactions
        if new_block.verify_transactions():
            self.chain.append(new_block)
            self.pending_transactions = [] 
            #print(f"Block mined and added to chain. Miner rewarded with 50 coins.")
        else:
            print("Block contains invalid transactions. Block rejected.")

    def to_json(self):
        return json.dumps(self.chain)

    def is_chain_valid(self):
        """Validate the entire blockchain."""
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

    def is_ammount_valid(self, transaction:Transaction):
        total = 0
        if transaction.recipient == transaction.sender:
            return False
        for block in self.chain:
            for t in block.transactions:
                if t.recipient == transaction.sender: #check if sender recieved coins
                    total += t.amount
                if t.sender == transaction.sender: #check if sender sent coins
                    total -= t.amount
        if total < transaction.amount:
            return False
        for t in self.pending_transactions: #check doublespent
            if t.recipient == transaction.sender: 
                total += t.amount
            if t.sender == transaction.sender: 
                total -= t.amount
        if total < 0:
            return False
        else:
            return True

    def display_chain(self):
        """Display the entire blockchain."""
        for block in self.chain:
            print(f"Block {block.index}:")
            print(f"  Timestamp: {block.timestamp}")
            print(f"  Transactions: {[tx.as_dict() for tx in block.transactions]}")
            print(f"  Hash: {block.hash}")
            print(f"  Previous Hash: {block.previous_hash}")
            print(f"  Nonce: {block.nonce}\n")

# Example Usage
if __name__ == "__main__":
    # Generate keys for sender and recipient using your seed-based function
    miner_public_key = get_public_key_from_seed("my_secure_seed", 0)

    recipient_public_key = get_public_key_from_seed("recipient_seed", 0)

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
    blockchain.display_chain()