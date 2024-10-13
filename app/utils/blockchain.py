import hashlib
import json
from time import time

class BlockchainBlock:
    def __init__(self, index, timestamp, data, previous_hash):
        self.index = index
        self.timestamp = timestamp
        self.data = data
        self.previous_hash = previous_hash
        self.nonce = 0
        self.hash = self.compute_hash()

    def compute_hash(self):
        block_string = json.dumps({
            'index': self.index,
            'timestamp': self.timestamp,
            'data': self.data,
            'previous_hash': self.previous_hash,
            'nonce': self.nonce
        }, sort_keys=True)
        return hashlib.sha256(block_string.encode()).hexdigest()

    def proof_of_work(self, difficulty=4):
        target = "0" * difficulty
        while not self.hash.startswith(target):
            self.nonce += 1
            self.hash = self.compute_hash()

class Blockchain:
    def __init__(self):
        self.chain = []
        self.create_genesis_block()

    def create_genesis_block(self):
        genesis_block = BlockchainBlock(0, time(), {"data": "Genesis Block"}, "0")
        genesis_block.proof_of_work()
        self.chain.append(genesis_block)

    def get_latest_block(self):
        return self.chain[-1]

    def add_block(self, data):
        previous_block = self.get_latest_block()
        new_block = BlockchainBlock(
            index=len(self.chain),
            timestamp=time(),
            data=data,
            previous_hash=previous_block.hash
        )
        new_block.proof_of_work()
        self.chain.append(new_block)
        return new_block

    def is_chain_valid(self):
        for i in range(1, len(self.chain)):
            current_block = self.chain[i]
            previous_block = self.chain[i - 1]

            if current_block.hash != current_block.compute_hash():
                return False

            if current_block.previous_hash != previous_block.hash:
                return False

        return True


