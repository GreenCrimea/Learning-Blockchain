"""
Botanic (PORT 5000)
By Tom Horton
7/3/22
*****

*****
ALPHA-v0.5
    changelog:
        v0.5 - added a mechanism to join a chain, cleaned up some print functions
        v0.4 - added automatic chain consensus and automatic node propagation
        v0.3 - added public and private key request and generation
        v0.2 - added docstrings and comments, removed temporary print commands used during debugging
        v0.1 - INIT
*****
This program will create a node that will hold a blockchain, or decentralized append-only ledger, with rudimentary
implementation of mining, consensus, validation, and transactions. the code uses flask to interact with GET and POST
requests in order to interact with the node.
"""

import datetime
import hashlib
import json
from flask import Flask, jsonify, request
import requests
from uuid import uuid4
from urllib.parse import urlparse
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from threading import Timer


this_node = "192.168.1.3:5001"


class RepeatedTimer(object):
    def __init__(self, interval, function, *args, **kwargs):
        self._timer = None
        self.interval = interval
        self.function = function
        self.args = args
        self.kwargs = kwargs
        self.is_running = False
        self.start()

    def _run(self):
        self.is_running = False
        self.start()
        self.function(*self.args, **self.kwargs)

    def start(self):
        if not self.is_running:
            self._timer = Timer(self.interval, self._run)
            print("\n...beep...\n")
            self._timer.start()
            self.is_running = True

    def stop(self):
        self._timer.cancel()
        self.is_running = False


class Blockchain:
    """contains all methods relating to the backend of the blockchain"""

    node = set()

    def __init__(self):
        self.chain = []
        self.transactions = []
        self.create_block(proof=1, previous_hash="0")
        self.node = set()

    def create_block(self, proof, previous_hash):
        """
        creates a block as a dictionary.
        re-initialises self.transactions back to empty after it is filled by the self.add_transactions method.
        appends the block to the current chain this machine is holding.
        """
        block = {"index": len(self.chain) + 1,
                 "timestamp": str(datetime.datetime.now()),
                 "proof": proof,
                 "previous_hash": previous_hash,
                 "transactions": self.transactions}
        self.transactions = []
        self.chain.append(block)
        return block

    def get_previous_block(self):
        """returns the index number of the previous block in the chain"""
        return self.chain[-1]

    def proof_of_work(self, previous_proof):
        """find golden hash and return the proof"""
        new_proof = 1
        check_proof = False
        while check_proof is False:
            hash_operation = hashlib.sha256(str(new_proof**2 - previous_proof**2).encode()).hexdigest()
            if hash_operation[:6] == "000000":  # change here AND function in is_chain_valid to adjust difficulty
                check_proof = True
            else:
                new_proof += 1
        return new_proof

    def hash(self, block):
        """hash entire block and return hashed output"""
        encoded_block = json.dumps(block, sort_keys=True).encode()
        return hashlib.sha256(encoded_block).hexdigest()

    def is_chain_valid(self, chain):
        """check if the chain is valid by comparing the blocks previous hash value to the calculated previous hash"""
        previous_block = chain[0]
        block_index = 1
        while block_index < len(chain):
            block = chain[block_index]
            if block["previous_hash"] != self.hash(previous_block):
                return False
            previous_proof = previous_block["proof"]
            proof = block["proof"]
            hash_operation = hashlib.sha256(str(proof**2 - previous_proof**2).encode()).hexdigest()
            if hash_operation[:6] != "000000":  # change here AND function in proof_of_work to adjust difficulty
                return False
            previous_block = block
            block_index += 1
        return True

    def add_transactions(self, sender, receiver, amount):
        """add transactions to be pushed into the next mined block"""
        self.transactions.append({"sender": sender,
                                  "receiver": receiver,
                                  "amount": amount})
        previous_block = self.get_previous_block()
        return previous_block["index"] + 1

    def add_node(self, address, new_node):
        """add the address of any nodes to the node set"""
        if address:
            parsed_url = urlparse(address)
            self.node.add(parsed_url.netloc)
        if new_node:
            parse_node = urlparse(new_node)
            self.node.add(parse_node.netloc)
        self.self_node()

    def replace_chain(self):
        """replace this machines chain if a node currently holds a longer valid chain"""
        network = self.node
        longest_chain = None
        max_length = len(self.chain)
        for node in network:
            response = requests.get(f"http://{node}/get_chain")
            if response.status_code == 200:
                length = response.json()["length"]
                chain = response.json()["chain"]
                if length > max_length:
                    if self.is_chain_valid(chain):
                        max_length = length
                        longest_chain = chain
        if longest_chain:
            self.chain = longest_chain
            return True
        return False

    def self_node(self):
        """make sure this machines address is not in its node set, as will cause infinite loop"""
        list_of_nodes = tuple(self.node)
        node_length = len(list_of_nodes)
        for a in range(node_length):
            if list_of_nodes[a] == this_node:
                list_nodes = set(list_of_nodes)
                list_nodes.remove(this_node)
                self.node = list_nodes
                a += 1

    def propagate_node(self, node):
        """propagate this machines nodes to all machines on the network"""
        self.self_node()
        list_of_nodes = tuple(self.node)
        node_length = len(list_of_nodes)
        if node_length > 1:
            for a in range(node_length):
                deliver_to = "http://" + list_of_nodes[a] + "/receive_propagation"
                requests.post(url=deliver_to, data=node)
                a += 1

    def receive_propagation(self, node):
        """receive the nodes from other machines"""
        self.node.add(node)
        self.self_node()



# create an index for saved user keys - security nightmare TODO fix
user_index = 0


class Cryptography:
    """Contains methods related to generating and requesting keys"""

    private_key = []
    public_key = []
    user = []

    def generate_key_object(self):
        """generate private key object"""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048)
        return private_key

    def request_keys(self, password):
        """create private and public keys, as well as UUID and user index. write information to public_key_log.txt
        and private_key_log.txt"""
        global user_index
        private_key_pass = password[0].encode()
        encrypted_pem_private_key = self.generate_key_object().private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(private_key_pass))
        pem_public_key = self.generate_key_object().public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo)
        user_identification = str(uuid4()).replace("-", " ")
        self.user.append(user_identification)
        private_key_file = open("private_key_log.txt", "a")
        private_key_file.write(f"INDEX = {user_index} - UUID = {user_identification}\n\nPRIVATE KEY = {encrypted_pem_private_key.decode()}\n---\n\n")
        private_key_file.close()
        public_key_file = open("public_key_log.txt", "a")
        public_key_file.write(f"INDEX = {user_index} - UUID = {user_identification}\n\nPUBLIC KEY = {pem_public_key.decode()}\n---\n\n")
        public_key_file.close()
        self.public_key.append(pem_public_key.decode())
        self.private_key.append(encrypted_pem_private_key.decode())


app = Flask(__name__)
app.config['JSONIFY_PRETTYPRINT_REGULAR'] = False   # Flask will return an error if this isnt included

node_address = str(uuid4()).replace("-", " ")

blockchain = Blockchain()
cryptography = Cryptography()

@app.route("/mine_block", methods=["GET"])
def mine_block():
    """Request to mine a block, collect mining reward and add block to this machines chain"""
    previous_block = blockchain.get_previous_block()
    previous_proof = previous_block["proof"]
    proof = blockchain.proof_of_work(previous_proof)
    previous_hash = blockchain.hash(previous_block)
    blockchain.add_transactions(sender=node_address, receiver="SELF", amount=10)    # this is the mining reward
    block = blockchain.create_block(proof, previous_hash)
    response = {"message": "Congratulations, your block has been mined and added to the Botanical Chain.",
                "index": block["index"],
                "timestamp": block["timestamp"],
                "proof": block["proof"],
                "previous_hash": block["previous_hash"],
                "transactions": block["transactions"]}
    return jsonify(response), 200


@app.route("/get_chain", methods=["GET"])
def get_chain():
    """request the current chain"""
    response = {"chain": blockchain.chain,
                "length": len(blockchain.chain)}
    return jsonify(response), 200


@app.route("/is_valid", methods=["GET"])
def is_valid():
    """request if the current chain is valid"""
    is_valid = blockchain.is_chain_valid(blockchain.chain)
    if is_valid:
        response = {"message": "This nodes Botanical Chain is currently valid"}
    else:
        response = {"message": f"This nodes Botanical Chain is *****INVALID*****"}
    return jsonify(response), 200


@app.route("/add_transaction", methods=["POST"])
def add_transaction():
    """
    add a transaction to the mempool to be added to the next mined block
    POST command formatted as application/json:
    {
        "sender": "",
        "receiver": "",
        "amount":
    }
    """
    json = request.get_json(force=True, silent=True, cache=False)
    transaction_keys = ["sender", "receiver", "amount"]
    if not all(key in json for key in transaction_keys):
        return "Transaction is missing information.\nRemember to enter Sender, Receiver, and Amount", 400
    index = blockchain.add_transactions(json["sender"], json["receiver"], json["amount"])
    response = {"message": f"This transaction will be added to Block #{index}"}
    return jsonify(response), 201


@app.route("/connect_node", methods=["POST"])
def connect_node():
    """
    request to connect to a node. Only include addresses of other nodes on the system not yourself.
    POST command formatted as application/json:
    {
        "nodes":   ["http://192.168.1.3:5000/",
                    "http://192.168.1.3:5001/",
                    "http://192.168.1.3:5002/",]
    }
    """
    json = request.get_json(force=True, silent=True, cache=False)
    nodes = json.get("nodes")
    if nodes is None:
        return "No Node", 400
    for nodes in nodes:
        blockchain.add_node(address=nodes, new_node=None)
    response = {"message": "All nodes Connected. The Botanical Chain now contains the nodes:",
                "total_nodes": list(blockchain.node)}
    return jsonify(response), 201


@app.route("/propagate_nodes", methods=["GET"])
def propagate_nodes():
    """sends this machines current nodes to all other machines on the network"""
    list_of_nodes = blockchain.node
    list_of_nodes.add(this_node)
    list_of_nodes = tuple(list_of_nodes)
    node_length = len(list_of_nodes)
    for a in range(node_length):
        blockchain.propagate_node(list_of_nodes[a])
        a += 1
    response = {"message": "Nodes have successfully propagated"}
    return jsonify(response), 201


def propagate_nodes_timer():
    """automatically sends this machines current nodes to all other machines on the network """
    list_of_nodes = blockchain.node
    list_of_nodes.add(this_node)
    list_of_nodes = tuple(list_of_nodes)
    node_length = len(list_of_nodes)
    for a in range(node_length):
        blockchain.propagate_node(list_of_nodes[a])
        a += 1
    print("Nodes have successfully propagated")


print("starting propagation timer, checking every 5 minutes")
rt_one = RepeatedTimer(300, propagate_nodes_timer)


@app.route("/receive_propagation", methods=["POST"])
def receive_propagation():
    """receive data from other machines on the network and update node list"""
    node = request.data.decode('utf-8')
    blockchain.receive_propagation(node)
    response = {"message": "Nodes have successfully propagated"}
    return jsonify(response), 201


@app.route("/join_chain", methods=["POST"])
def join_chain():
    """
    join the chain by sending your current address.
    POST command formatted as application/json:
    {
        "address":   ["http://192.168.1.3:5000/"]
    }
    """
    json = request.get_json(force=True, silent=True, cache=False)
    new_node = str(json.get("address"))
    new_node = new_node.replace("[", "")
    new_node = new_node.replace("]", "")
    new_node = new_node.replace("'", "")
    new_node = new_node.replace("'", "")
    blockchain.add_node(address=None, new_node=new_node)
    blockchain.propagate_node(new_node)
    response = {"message": "You have successfully joined the botanical chain"}
    return jsonify(response), 201


@app.route("/replace_chain", methods=["GET"])
def replace_chain():
    """request to update this machines chain to the longest in the network"""
    is_chain_replaced = blockchain.replace_chain()
    if is_chain_replaced:
        response = {"message": "The node's chain has been replaced with the current longest chain.",
                    "new_chain": blockchain.chain}
    else:
        response = {"message": "The current chain is the longest.",
                    "actual_chain": blockchain.chain}
    return jsonify(response), 200


def replace_chain_timer():
    """request to update this machines chain to the longest in the network - triggered automatically"""
    is_chain_replaced = blockchain.replace_chain()
    if is_chain_replaced:
        print(f"The node's chain has been replaced with the current longest chain.")
    else:
        print(f"The current chain is the longest.")


print("starting consensus timer, checking every 1 minute")
rt_two = RepeatedTimer(60, replace_chain_timer)


@app.route("/request_keys", methods=["POST"])
def request_keys():
    """
    Request to create and send public and private keys, as well as a linked UUID
    POST command formatted as application/json:
    {
        "private_key_password":     ["Password"]
    }
    """
    global user_index
    json = request.get_json(force=True, silent=True, cache=False)
    private_key_password = json.get("private_key_password")
    Cryptography().request_keys(password=private_key_password)
    public_key = cryptography.public_key[user_index]
    private_key = cryptography.private_key[user_index]
    user = cryptography.user[user_index]
    response = {"message": "Your keys have been created. KEEP YOUR PRIVATE KEY AND PASSWORD SAFE!!!",
                "Public_key": public_key,
                "Private_key": private_key,
                "UUID": user,
                "INDEX": user_index}
    user_index += 1
    return jsonify(response), 200


@app.route("/see_nodes", methods=["GET"])
def see_nodes():
    """return the nodes in this machines list"""
    nodes = list(blockchain.node)
    response = {"message": nodes}
    return jsonify(response), 200


app.run(host="0.0.0.0", port=5001)      # change port to run multiple instances on a single machine for development
