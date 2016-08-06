import json
import urlparse
import urllib
import hashlib
import base64
import time
import random

import squeakspace.common.squeak_ex as ex

import Crypto.Random.random

from Crypto.Cipher import PKCS1_OAEP
from Crypto.Cipher import AES
from Crypto.Signature import PKCS1_PSS
from Crypto.Hash import SHA
from Crypto.PublicKey import RSA

## The ciphertext is two base64 strings, separated by a "|" character.
## The first base64 string is a PKCS1_OAEP ciphertext of
## a random 16 byte AES key concatenated with a random 16 byte iv vector.
## The base64 string after the | separator is the AES ciphertext with padding.
## The last 16 byte block of the padded plaintext is an ascii string
## representing the number of extra bytes in padding. The rest of
## padding are null bytes.

## I encourage readers to scrutinize this or recommend a replacement.

class CryptSqueak:
    standard = "squeak"
    name = "pyCrypto.squeak"

    def __init__(self):
        self.random = Crypto.Random.new()
        self.int_random = Crypto.Random.random.StrongRandom()

        # constants
        self.aes_mode = AES.MODE_CBC
        self.rand_pad_min = 1 # must be at least one for the padding length block.
        self.rand_pad_max = 4*1024/16 ## 4kb of file size noise.

    # Keys are RSA.
    def assert_public_key(self, key, argument):
        try:
            key_obj = RSA.importKey(key)
            assert(key_obj.has_private() == False)
        except Exception:
            raise ex.BadKeyException(argument)
    
    # Signatures use PKCS1_PSS
    def verify_signature(self, public_key, data, signature):
        try:
            key = RSA.importKey(public_key)
        except ValueError as e:
            raise ex.BadKeyException('signing key')

        verifier = PKCS1_PSS.new(key)
        hash = SHA.new()
        hash.update(data)
        bin_signature = base64.urlsafe_b64decode(str(signature))

        try:
            return verifier.verify(hash, bin_signature)
        except ValueError as e:
            return False

    def assert_passphrase(self, private_key, passphrase):
        try:
            key = RSA.importKey(private_key, passphrase=passphrase)
        except ValueError:
            raise ex.SimpleBadPassphraseException()

    
    def sign(self, private_key, data, passphrase=None):
        try:
            key = RSA.importKey(private_key, passphrase=passphrase)
        except ValueError:
            raise ex.SimpleBadPassphraseException()

        signer = PKCS1_PSS.new(key)
        hash = SHA.new()
        hash.update(data)
        signature = signer.sign(hash)

        return base64.urlsafe_b64encode(signature)

    
    def encrypt(self, public_key, data):

        try:
            rsa_key = RSA.importKey(public_key)
        except ValueError:
            raise ex.BadKeyException('encryption key')

        aes_key = self.random.read(16)
        iv = self.random.read(AES.block_size)

        aes_key_iv = aes_key + iv

        data_rem = len(data) % 16
        extra_blocks = self.int_random.randint(self.rand_pad_min, self.rand_pad_max)
        extra_bytes = extra_blocks*16

        if data_rem != 0:
            extra_bytes += (16 - data_rem)

        extra_bytes_str = str(extra_bytes)
        assert(len(extra_bytes_str) <= 16)
        extra_bytes_str_padding = (16 - len(extra_bytes_str)) * '0'
        extra_bytes_str = extra_bytes_str_padding + extra_bytes_str

        extra_zeros = extra_bytes - len(extra_bytes_str)
        assert(extra_zeros >= 0)

        padded_plaintext = data + ('\x00' * extra_zeros) + extra_bytes_str

        sym_cipher = AES.new(aes_key, self.aes_mode, iv)

        aes_ciphertext = sym_cipher.encrypt(padded_plaintext)
        
        asym_cipher = PKCS1_OAEP.new(rsa_key)

        aes_key_iv_ciphertext = asym_cipher.encrypt(aes_key_iv)

        return base64.urlsafe_b64encode(aes_key_iv_ciphertext) + '|' + base64.urlsafe_b64encode(aes_ciphertext)

    
    def decrypt(self, private_key, data, passphrase=None):

        try:
            rsa_key = RSA.importKey(private_key, passphrase=passphrase)
        except ValueError:
            raise ex.SimpleBadPassphraseException()

        components = data.split('|')
        if len(components) != 2:
            raise ex.BadCiphertextException()

        aes_key_and_iv_ciphertext = base64.urlsafe_b64decode(str(components[0]))
        aes_ciphertext = base64.urlsafe_b64decode(str(components[1]))

        asym_cipher = PKCS1_OAEP.new(rsa_key)
        aes_key_and_iv = asym_cipher.decrypt(aes_key_and_iv_ciphertext)

        if len(aes_key_and_iv) != 32:
            raise ex.BadCiphertextException()

        aes_key = aes_key_and_iv[:16]
        iv = aes_key_and_iv[16:]

        sym_cipher = AES.new(aes_key, self.aes_mode, iv)
        padded_plaintext = sym_cipher.decrypt(aes_ciphertext)

        last_block = padded_plaintext[-16:]

        try:
            padding_length = int(last_block)
        except ValueError:
            raise ex.BadCiphertextException()

        if padding_length < 16 or padding_length > len(padded_plaintext):
            raise ex.BadCiphertextException()

        plaintext_length = len(padded_plaintext) - padding_length

        plaintext = padded_plaintext[:plaintext_length]

        return plaintext


    
    def create_keypair(self, kwords):

        try:
            bits = kwords['bits']
            passphrase = kwords.get('passphrase')

            key = RSA.generate(bits)
            pub_key = key.publickey()

            key_str = key.exportKey('PEM', passphrase=passphrase)
            pub_key_str = pub_key.exportKey('PEM')

            return (pub_key_str, key_str)

        except ValueError:
            raise ex.BadKeyParametersException(kwords)
        
