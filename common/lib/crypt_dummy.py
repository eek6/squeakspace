
import json
import urlparse
import urllib
import hashlib
import base64
import time
import random

import squeak_ex as ex

# This dummy encryption is just to help debugging.
# Don't enable otherwise.
class CryptDummy:
    standard = "dummy"
    name = "dummy"

    def assert_public_key(self, key, argument):
        pass
    
    def verify_signature(self, public_key, data, signature):
        try:
            (start, priv, dat) = signature.split('|')
    
            return (int(priv) == int(public_key) * 2) and (dat == data)
    
        except:
            return False
    
    def sign(self, private_key, data, passphrase=None):
        return 'signature|' + private_key + '|' + data
    
    def encrypt(self, public_key, data):
        return 'encrypted' + data
    
    def decrypt(self, private_key, data, passphrase=None):
        start = 'encrypted'
        assert(len(data) >= start)
        assert(data[:len(start)] == start)
        return data[len(start):]
    
    def create_keypair(self, kwords):
        # This is a dummy routine.
        num = random.randint(0,1000000)
        pub = str(num)
        priv = str(num * 2)
        return (pub, priv)
    
    
