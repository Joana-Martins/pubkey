import hashlib
import json
import operator
import os
import random
import sys
import time
import pandas as pd
import paho.mqtt.client as mqtt

from multiprocessing import Process, Value
from threading import Event, Thread
from bitstring import BitArray
from queue import Queue
from Crypto.Hash import SHA256
from Crypto.Signature import PKCS1_v1_5
from Crypto.PublicKey import RSA

class KeyPeer:
    def __init__(self):
        self.client = mqtt.Client()
        self.msg_queues = {
            'NodeName': Queue(),
            'PubKey': Queue()
        }

    def exportKey(self):
        with open("private_key.pem", "r") as src:
            private_key = RSA.importKey(src.read())

        public_key = private_key.publickey()

        with open('public_key.txt', 'w') as out:
            out.write(public_key.exportKey().decode('utf-8'))

    def sign (self):
        message = input("Enter a message: ")
        digest = SHA256.new()
        digest.update(message.encode('utf-8'))
        with open ("private_key.pem", "r") as myfile:
            private_key = RSA.importKey(myfile.read())
        signer = PKCS1_v1_5.new(private_key)
        sig = signer.sign(digest)
        self.client.publish('pdd/pubkey', message)
        #print("Signature: ")
        #print(sig.hex())

    def connect(self, broker_address):
        self.id = time.time_ns()
        self.broker_address = broker_address
        self.client.connect(broker_address)
        print(f'{self.id}: Connected to broker')

    def run(self):
        print(f'{self.id}: Started transaction mining')
        self.client.subscribe('pdd/pubkey')
        self.sign()


address = sys.argv[1]
key_peer = KeyPeer()
key_peer.exportKey()
key_peer.connect(address)
key_peer.run()
