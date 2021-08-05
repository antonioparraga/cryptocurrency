import unittest
import hashlib
import time
import json
import rsa
import random
from p2pnetwork.node import Node

class BlockChain(Node):

    def __init__(self, host='127.0.0.1', port=None):
        self.blocks = []
        self.current_transactions = []
        self.blocks = []
        self.nodes = []
        self.difficulty = 4 #represents the number of zeros that are required to be in the hash
        if port == None:
            random.seed()
            port = random.randint(10000, 20000)
        super(BlockChain, self).__init__(host, port)    
        self.start()

    def new_block(self):
        previous_hash = None
        if(len(self.blocks) > 0):
            previous_hash = self.blocks[-1].hash
        block = Block(len(self.blocks), time.time(), self.current_transactions, previous_hash)
        block.mine_block(self.difficulty)
        self.blocks.append(block)
        self.current_transactions = []
        return block

    def add_block(self, block):
        self.blocks.append(block)

    def new_transaction(self, sender, recipient, amount):

        pem_file = open("public_key.pem", "r")
        key_data = pem_file.read()
        pem_file.close()
        public_key = rsa.PublicKey.load_pkcs1(key_data, 'PEM')

        pem_file = open("private_key.pem", "r")
        key_data = pem_file.read()
        pem_file.close()
        private_key = rsa.PrivateKey.load_pkcs1(key_data, 'PEM')

        transaction = Transaction(sender, recipient, amount, time.time())
        transaction.sign(private_key, public_key)
        if transaction.is_valid():
            self.current_transactions.append(transaction)
            return True

    def generate_keys(self):
        key = rsa.newkeys(2048)
        public_key = key[0]
        private_key = key[1]

        file_out = open("public_key.pem", "w")
        file_out.write(public_key.save_pkcs1(format='PEM').decode('UTF-8'))
        file_out.close()

        file_out = open("private_key.pem", "w")
        file_out.write(private_key.save_pkcs1(format='PEM').decode('UTF-8'))
        file_out.close()


    @staticmethod
    def hash(block):
        # Hashes a Block
        pass

    @property
    def last_block(self):
        # Returns the last Block in the chain
        pass

    def proof_of_work(self, last_proof):
        # Simple Proof of Work Algorithm
        pass

    @staticmethod
    def valid_proof(last_proof, proof):
        # Validates the Proof: Does hash(last_proof, proof) contain 4 leading zeroes?
        pass

    @staticmethod
    def valid_chain(chain):
        # Determine if a given blockchain is valid
        pass

    def resolve_conflicts(self):
        # Consensus Algorithm: resolves conflicts by replacing our chain with the longest one in the network
        pass

    def register_node(self, host, port):
        self.nodes.append({"host": host, "port": port})

    def perform_consensus(self):
        # Perform consensus algorithm
        for node in self.nodes:
            self.connect_with_node(node["host"], node["port"])

    def inbound_node_connected(self, connected_node):
        self.send_to_nodes(self.json_encode())        

    def node_message(self, connected_node, message):
        data_json = json.JSONEncoder().encode(message)
        result_dict = json.loads(data_json)
        blocks = []
        for block_dict in result_dict["blocks"]:
            transactions_dict = block_dict["transactions"]
            transactions = []
            for transaction_dict in transactions_dict:
                transactions.append(Transaction(**transaction_dict))
            new_block = Block(**block_dict)
            new_block.transactions = transactions
            blocks.append(new_block)

        if len(blocks) > len(self.blocks):
            self.blocks = blocks
            self.current_transactions = []
            print("Received chain is bigger than currrent one, so current one will be replaced by received one")
            return True        
        else:
            print("Received chain is not bigger than current one, so current one will be kept")
            return False    

    def repr_json(self):
        return {
            "blocks": [block.repr_json() for block in self.blocks],
            "current_transactions": [transaction.repr_json() for transaction in self.current_transactions]
        }

    def json_encode(self):
        return json.JSONEncoder().encode(self.repr_json())


class Block(object):
    def __init__(self, index, timestamp, transactions, previous_hash, proof=None, *args, **kwargs):
        self.index = index
        self.timestamp = timestamp
        self.transactions = transactions
        self.previous_hash = previous_hash
        self.proof = proof

    def mine_block(self, difficulty):
        # Proof of Work Algorithm
        proof = self.proof_of_work(difficulty)
        self.proof = proof
        return proof

    def proof_of_work(self, difficulty):
        proof = 0
        while self.valid_proof(proof, difficulty) is False:
            proof += 1
        return proof        

    def valid_proof(self, proof, difficulty):
        hash = hashlib.sha256((str(self.index) + str(self.timestamp) + "".join(list(map(lambda x: x.hash, self.transactions))) + str(self.previous_hash) + str(proof)).encode('utf-8')).hexdigest()
        return hash[:difficulty] == '0'*difficulty

    @property
    def hash(self):
        return hashlib.sha256((str(self.index) + str(self.timestamp) + "".join(list(map(lambda x: x.hash, self.transactions))) + str(self.previous_hash) + str(self.proof)).encode('utf-8')).hexdigest()

    def repr_json(self):
        return {
            "hash": self.hash,
            "index": self.index,
            "timestamp": self.timestamp,
            "transactions": list(map(lambda x: x.repr_json(), self.transactions)),
            "previous_hash": self.previous_hash,
            "proof": self.proof
        }


class Transaction(object):
    def __init__(self, sender, receiver, amount, timestamp, *args, **kwargs):
        self.sender = sender
        self.receiver = receiver
        self.amount = amount
        self.timestamp = timestamp
        self.public_key = None
        self.signature = None

    def sign(self, private_key, public_key):
        self.public_key = public_key
        self.signature = rsa.sign(self.hash.encode('utf-8'), private_key, 'SHA-256')

    def is_valid(self):
        if rsa.verify(self.hash.encode('utf-8'), self.signature, self.public_key):
            return True
        return False    

    @property
    def hash(self):
        return hashlib.sha256((str(self.sender) + str(self.receiver) + str(self.amount) + str(self.timestamp)).encode('utf-8')).hexdigest()

    def repr_json(self):
        return {
            "sender": self.sender,
            "receiver": self.receiver,
            "amount": self.amount,
            "timestamp": self.timestamp,
            "hash": self.hash
        }


class ComplexEncoder(json.JSONEncoder):

    def default(self, obj):
        if hasattr(obj, 'repr_json'):
            return obj.repr_json()
        else:
            return json.JSONEncoder.default(self, obj, sort_keys=True, indent=4)    


class TestBlockChain(unittest.TestCase):
    def setUp(self):
        self.blockchain = BlockChain()

    def test_new_block(self):
        self.blockchain.new_block()
        self.assertEqual(len(self.blockchain.blocks), 1)
        self.assertEqual(self.blockchain.blocks[0].index, 0)
        self.assertEqual(self.blockchain.blocks[0].transactions, [])
        self.assertEqual(self.blockchain.blocks[0].previous_hash, None)

    def test_add_block(self):
        first_block = self.blockchain.new_block()
        second_block = self.blockchain.new_block()
        third_block = self.blockchain.new_block()
        self.assertEqual(self.blockchain.blocks[0].hash, first_block.hash)
        self.assertEqual(self.blockchain.blocks[1].hash, second_block.hash)
        self.assertEqual(self.blockchain.blocks[2].hash, third_block.hash)
        self.assertEqual(len(self.blockchain.blocks), 3)
        print(json.dumps(self.blockchain.repr_json(), cls=ComplexEncoder, sort_keys=True, indent=4))

    def test_keys(self):
        self.blockchain.generate_keys()

    def test_new_transaction(self):
        self.blockchain.new_transaction("Alice", "Bob", 100)
        self.assertEqual(len(self.blockchain.current_transactions), 1)
        self.assertEqual(self.blockchain.current_transactions[0].sender, "Alice")
        self.assertEqual(self.blockchain.current_transactions[0].receiver, "Bob")
        self.assertEqual(self.blockchain.current_transactions[0].amount, 100)
        self.blockchain.new_block()
        self.assertEqual(len(self.blockchain.current_transactions), 0)
        self.assertEqual(len(self.blockchain.blocks), 1)
        print(json.dumps(self.blockchain.repr_json(), cls=ComplexEncoder, sort_keys=True, indent=4))

    def test_p2p(self):
        blockchain1 = BlockChain('127.0.0.1', 60001)
        blockchain2 = BlockChain('127.0.0.1', 60002)

        blockchain1.register_node('127.0.0.1', 60002)
        blockchain2.register_node('127.0.0.1', 60001)

        blockchain1.new_transaction("Alice", "Bob", 100)
        blockchain1.new_transaction("Bob", "Alice", 20)
        blockchain1.new_block()

        blockchain2.perform_consensus()
        print(json.dumps(blockchain1.repr_json(), cls=ComplexEncoder, sort_keys=True, indent=4))
        print(json.dumps(blockchain2.repr_json(), cls=ComplexEncoder, sort_keys=True, indent=4))


if __name__ == '__main__':
    unittest.main()
