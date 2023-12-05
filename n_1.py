import datetime
import hashlib
import json
from flask import Flask, jsonify, request
import requests
from uuid import uuid4
from urllib.parse import urlparse
####################
from cryptography.hazmat.primitives import serialization as crypto_serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend as crypto_default_backend
from ecdsa import SigningKey
import ecdsa
import codecs
import mysql.connector
import pandas as pd
from sqlalchemy import create_engine

mysqldb = create_engine('mysql+mysqlconnector://root:1234@localhost:3306/test', echo = False)

def insert(df, name, mode='replace'):
    print(df)
    df.to_sql(name = name, con = mysqldb, if_exists =mode, chunksize = 10000, index=False);

# Part 1 - Building a Blockchain

class Blockchain:

    def __init__(self):
        self.chain = []
        self.transactions = []
        self.create_block(proof=1, previous_hash='0')
        self.nodes = set()
        self.users = {}

    def create_block(self, proof, previous_hash):
        block = {'index': len(self.chain) + 1,
                 'timestamp': str(datetime.datetime.now()),
                 'proof': proof,
                 'previous_hash': previous_hash,
                 'transactions': self.transactions,
                 'hash': self.hash({"transaction":self.transactions})
                 }

        self.chain.append(block)
        block_write = {'index': [len(self.chain)],
                 'timestamp': [str(datetime.datetime.now())],
                 'proof': [proof],
                 'previous_hash': [previous_hash],
                 'txns': [str(self.transactions)],
                 'hash': [self.hash({"transaction":self.transactions})]
                 }
        # print(block)
        self.transactions = []

        if(previous_hash == '0'):
            print('new')
            insert(pd.DataFrame(block_write), 'tbl_blocks', 'replace')
        else:
            print('old')
            insert(pd.DataFrame(block_write), 'tbl_blocks', 'append')
        return block

    def get_previous_block(self):
        return self.chain[-1]

    def proof_of_work(self, previous_proof):
        new_proof = 1
        check_proof = False
        while check_proof is False:
            hash_operation = hashlib.sha256(str(new_proof ** 2 - previous_proof ** 2).encode()).hexdigest()
            if hash_operation[:4] == '0000':
                check_proof = True
            else:
                new_proof += 1
        return new_proof

    def hash(self, block):
        encoded_block = json.dumps(block, sort_keys=True).encode()
        return hashlib.sha256(encoded_block).hexdigest()

    def is_chain_valid(self, chain):
        previous_block = chain[0]
        block_index = 1
        while block_index < len(chain):
            block = chain[block_index]
            if("Create" in chain[block_index]["transactions"][0]["data"].replace("\'", "\"")):
                txn = pd.DataFrame(json.loads(chain[block_index]["transactions"][0]["data"].replace("\'", "\""))["Create"])
                print("Created following relation from current status in chain - \n", txn)
            if block['previous_hash'] != self.hash(previous_block):
                return False
            previous_proof = previous_block['proof']
            proof = block['proof']
            hash_operation = hashlib.sha256(str(proof ** 2 - previous_proof ** 2).encode()).hexdigest()
            if hash_operation[:4] != '0000':
                return False
            previous_block = block
            block_index += 1
        return True

    def add_transaction(self, sender, receiver, amount, data):

        if(sender != 'LV'):

            with open(sender+".json", "r") as fp:
                send_data = json.load(fp)
                # send_data = json.loads(send_data)
                send_public_key = send_data["public_key"]
                send_private_key = send_data["private_key"]
                issend_valid = self.validate_signature(send_public_key,send_private_key,sender)

            sender_utxo= self.get_utxo(sender)
        
        else:
            issend_valid = True
            # curr_bal = self.update_wallet(receiver, amount)
        
        sender_utxo = 999
        with open(receiver+".json", "r") as fm:
            rec_data = json.load(fm)
            rec_public_key = rec_data["public_key"]
            rec_private_key = rec_data["private_key"]
            isrec_valid = self.validate_signature(rec_public_key,rec_private_key,receiver)

        receiver_utxo = self.get_utxo(receiver)

        if sender_utxo>= amount:
            if issend_valid and isrec_valid:
                if(sender != 'LV'):
                    curr_bal = self.update_wallet(sender, -amount)
                print(amount)
                curr_bal = self.update_wallet(receiver, amount)
                
                
                self.transactions.append({'sender': sender,
                                          'receiver': receiver,
                                          'amount': amount,
                                          'data': data})
                previous_block = self.get_previous_block()
                # print(pd.DataFrame({'sender': sender,
                #                           'receiver': receiver,
                #                           'amount': amount,
                #                           'block': previous_block['index'] + 1}))
                insert(pd.DataFrame({'sender': [sender],
                                          'receiver': [receiver],
                                          'amount': [amount],
                                          'block': [previous_block['index'] + 1]}), 'tbl_transactions', 'append')

                
                return previous_block['index'] + 1
            else:
                return "Invalid Transaction"

    def get_utxo(self, user):
        with open(user + ".json", "r") as fp:
            user_data = json.load(fp)
            utxo = user_data["cash"]

        return utxo

    def update_wallet(self, user,amount):
        with open(user + ".json", "r") as fp:
            user_data = json.load(fp)
            print(user, user_data)
            utxo = user_data["cash"]
            curr_bal = utxo+amount
            if(curr_bal < 0):
                return -1
            print(utxo, curr_bal)
            user_data["cash"] = curr_bal
        data_json = json.dumps(user_data)
        with open(str(user) + ".json", "w+") as fm:
                fm.write(data_json)
        return curr_bal



    def add_node(self, address):
        parsed_url = urlparse(address)
        print(parsed_url)
        self.nodes.add(parsed_url.netloc)

    def replace_chain(self):
        network = self.nodes
        longest_chain = None
        max_length = len(self.chain)
        for node in network:
            response = requests.get(f'http://{node}/get_chain')
            if response.status_code == 200:
                length = response.json()['length']
                chain = response.json()['chain']
                if length > max_length and self.is_chain_valid(chain):
                    max_length = length
                    longest_chain = chain
        if longest_chain:
            self.chain = longest_chain
            return True
        return False


    def add_user(self, name):

        private_key = SigningKey.generate()
        public_key = private_key.verifying_key


        encoded_pubkey= json.dumps(str(public_key.to_string()), sort_keys=True).encode()
        hashed_pubkey = hashlib.sha256(encoded_pubkey).hexdigest()

        with open("user_details.json","a+") as fp:
            fp.seek(0)
            data = fp.read()
            print(data)
            data = {} if len(data) == 0 else json.loads(str(data))
            data[hashed_pubkey] = name

            data_json = json.dumps(data)
            with open("user_details.json", "w+") as fm:
                print(data_json)
                fm.write(data_json)

                insert(pd.DataFrame({'hashed_pubkey':[hashed_pubkey], 'name': [name]}), 'tbl_users', 'append')


        data1 = {"private_key":private_key.to_string().hex(),"public_key":public_key.to_string().hex(),"cash":0}




        data_json = json.dumps(data1)
        with open (str(hashed_pubkey)+".json","w+") as fm:
            fm.write(data_json)

    

    def update_userfile(self):
        network = self.nodes
        print(network)
        for node in network:
            response = requests.get(f'http://{node}/get_user')
            # if response.status_code == 200:
            #     length = response.json()['length']
            #
                # chain = response.json()['chain']
            chain_users =  response.json()
            print(chain_users)
            with open("user_details.json", "a+") as fp:
                
                fp.seek(0)
                data = fp.read()
                print(data)
                data = {} if len(data) == 0 else json.loads(str(data))

                for key,val in chain_users.items():
                    if key not in data.keys():
                        user_name = chain_users[key]
                        data[key] = user_name
                data_obj = json.dumps(data)
                with open("user_details.json", "w+") as fm:
                    fm.write(data_obj)

    def hash_keys(self,key):
        encoded_pubkey = json.dumps(str(key), sort_keys=True).encode()
        hashed_pubkey = hashlib.sha256(encoded_pubkey).hexdigest()
        return hashed_pubkey

    def validate_signature(self,public_key, private_key, hashed_pubkey):

        #private_key = SigningKey.generate()  # uses NIST192p
        priv_hex = codecs.decode(private_key, 'hex')
        print(type(priv_hex))
        signature = ecdsa.SigningKey.from_string(priv_hex).sign(bytes(hashed_pubkey, 'utf-8'))
        print(signature)
        #public_key = private_key.verifying_key
        #print("Verified:", )
        return ecdsa.VerifyingKey.from_string(codecs.decode(public_key, 'hex')).verify(signature, bytes(hashed_pubkey, 'utf-8'))









# Part 2 - Mining our Blockchain

# Creating a Web App
app = Flask(__name__)

# Creating an address for the node on Port 5001
node_address = str(uuid4()).replace('-', '')

# Creating a Blockchain
blockchain = Blockchain()


# Mining a new block
@app.route('/mine_block/<user>', methods=['GET'])
def mine_block(user):
    print(user)
    previous_block = blockchain.get_previous_block()
    previous_proof = previous_block['proof']
    proof = blockchain.proof_of_work(previous_proof)
    previous_hash = blockchain.hash(previous_block)
    user_pubkey = user
    with open("user_details.json", 'r') as fp:
        try:
            with open("user_details.json", 'r') as fp:
                data = json.load(fp)
                user_list = data.keys()
        except Exception as e:
            user_list = {}


        if not user_pubkey in user_list:
            return 'User is  missing, Mining not allowed', 400





    blockchain.add_transaction(sender='LV', receiver=user, amount=1, data='')
    block = blockchain.create_block(proof, previous_hash)
    response = {'message': 'Congratulations, you just mined a block!',
                'index': block['index'],
                'timestamp': block['timestamp'],
                'proof': block['proof'],
                'previous_hash': block['previous_hash'],
                'transactions': block['transactions']
                }
    return jsonify(response), 200


# Getting the full Blockchain
@app.route('/get_chain', methods=['GET'])
def get_chain():
    response = {'chain': blockchain.chain,
                'length': len(blockchain.chain)}
    return jsonify(response), 200

# Getting the full Blockchain
@app.route('/update_users', methods=['GET'])
def call_update_userfile():
    
    blockchain.update_userfile()
    return 'successful', 200


# get api to get user details of each node
@app.route('/get_user', methods=['GET'])
def get_user():
    try:
        with open("user_details.json", 'r') as fp:
            data = json.load(fp)
        return jsonify(data), 200
    except Exception as e:
        return jsonify({}), 200


@app.route('/add_user/<name>', methods=['GET'])
def add_user_call(name):
    blockchain.add_user(name)
    return "Created user "+name, 200


# Checking if the Blockchain is valid
@app.route('/is_valid', methods=['GET'])
def is_valid():
    is_valid = blockchain.is_chain_valid(blockchain.chain)
    if is_valid:
        response = {'message': 'All good. The Blockchain is valid.'}
    else:
        response = {'message': 'Houston, we have a problem. The Blockchain is not valid.'}
    return jsonify(response), 200


# Adding a new transaction to the Blockchain
@app.route('/add_transaction', methods=['POST'])
def add_transaction():
    json_rcv = request.get_json()
    transaction_keys = ['sender', 'receiver', 'amount', 'data']


    if not all(key in json_rcv for key in transaction_keys):
        return 'Some elements of the transaction are missing', 400

    with open("user_details.json", 'r') as fp:
        try:
            with open("user_details.json", 'r') as fp:
                data = json.load(fp)
                user_list = data.keys()
        except Exception as e:
            user_list = {}

        if not json_rcv['sender'] in user_list:
            return 'Sender is  missing', 400
        if not json_rcv['receiver'] in user_list:
            return 'Receiver is missing', 400



    index = blockchain.add_transaction(json_rcv['sender'], json_rcv['receiver'], json_rcv['amount'], json_rcv['data'])

    response = {'message': f'This transaction will be added to Block {index}'} if index is not None else {'message': f'This transaction cannot be added, insufficient balance'}


    return jsonify(response), 201







# Part 3 - Decentralizing our Blockchain




# Connecting new nodes
@app.route('/connect_node', methods=['POST'])
def connect_node():
    json = request.get_json()
    nodes = json.get('nodes')
    if nodes is None:
        return "No node", 400
    for node in nodes:
        blockchain.add_node(node)
    response = {'message': 'All the local nodes are now connected. The Custom Blockchain now contains the following nodes:',
                'total_nodes': list(blockchain.nodes)}
    return jsonify(response), 201


# Replacing the chain by the longest chain if needed
@app.route('/replace_chain', methods=['GET'])
def replace_chain():
    is_chain_replaced = blockchain.replace_chain()
    if is_chain_replaced:
        response = {'message': 'The nodes had different chains so the chain was replaced by the longest one.',
                    'new_chain': blockchain.chain}
    else:
        response = {'message': 'All good. The chain is the largest one.',
                    'actual_chain': blockchain.chain}
    return jsonify(response), 200


# Running the app
app.run(host='0.0.0.0', port=5001)
