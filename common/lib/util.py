import json
import urlparse
import urllib
import hashlib
import base64
import time
import random
import crypt_all
import proof_of_work_all

import squeak_ex as ex

def serialize_request(request):
    return json.dumps(request)

# use milliseconds
def current_time():
    return int(time.time() * 1000)

def timestamp_fresh(timestamp, curr, acceptable_future, acceptable_delay):
    diff = curr - timestamp
    return acceptable_future <= diff and diff <= acceptable_delay

def assert_timestamp(timestamp, argument):
    if type(timestamp) != int and type(timestamp) != long:
        raise ex.MalformedTimeStampException(timestamp, argument)

def assert_timestamp_fresh(timestamp, argument, acceptable_future, acceptable_delay):
    assert_timestamp(timestamp, argument)
    curr = current_time()
    if not timestamp_fresh(timestamp, curr, acceptable_future, acceptable_delay):
        raise ex.ExpiredTimeStampException(timestamp, curr, acceptable_delay, argument)

def parse_proof_of_work_parameters(parameters):
    return json.loads(parameters)

def assert_proof_of_work_args(parameters, argument):
    try:
        obj = parse_proof_of_work_parameters(parameters)
        algorithm = obj['algorithm']
        work_prover = proof_of_work_all.alg_map[algorithm]
        work_prover.assert_parameters(obj, parameters, argument)

    except ValueError:
        raise ex.MalformedProofOfWorkParametersException(parameters, argument)

def make_proof_of_work(parameters, data):
    obj = parse_proof_of_work_parameters(parameters)
    try:
        algorithm = obj['algorithm']
        work_prover = proof_of_work_all.alg_map[algorithm]
        return work_prover.work(obj, data)

    except ValueError:
        raise ex.MalformedProofOfWorkParametersException(parameters, argument)

def verify_proof_of_work(parameters, data, proof):
    obj = parse_proof_of_work_parameters(parameters)
    try:
        algorithm = obj['algorithm']
        work_checker = proof_of_work_all.alg_map[algorithm]
        return work_checker.verify_proof(obj, data, proof)

    except ValueError:
        raise ex.MalformedProofOfWorkParametersException(parameters, argument)
     

def hash_function(data):
    hash = hashlib.sha256()
    hash.update(str(len(data)))
    hash.update('|')
    hash.update(data)
    return base64.urlsafe_b64encode(hash.digest())


def verify_hash(data, hash):
    return hash_function(data) == hash


def assert_signature(key_type, public_key, data, signature, argument):

    if signature == None:
        raise ex.SignatureNullException()

    alg = crypt_all.find_alg(key_type)

    if not alg.verify_signature(public_key, data, signature):
        raise ex.BadSignatureException(key_type, public_key, data, signature, argument)

def assert_proof_of_work(parameters, data, proof_of_work, argument):
    if proof_of_work == None:
        raise ex.ProofOfWorkRequiredException(parameters, data, argument)

    if not verify_proof_of_work(parameters, data, proof_of_work):
        raise ex.BadProofOfWorkException(parameters, data, proof_of_work, argument)

def assert_hash(data, hash, argument):
    calc_hash = hash_function(data)
    #print ('assert_hash: ', ('data', data), ('hash', hash), ('calc_hash', calc_hash), ('argument', argument))
    if calc_hash != hash:
        raise ex.BadHashException(argument, data, hash, calc_hash)

def assert_node_name(given_node_name, node_name):
    if given_node_name != node_name:
        raise ex.BadNodeNameException(given_node_name, node_name)

def hash_public_key(key_type, public_key):
    key_str = json.dumps([key_type, public_key])
    return hash_function(key_str)

def assert_public_key_hash(key_type, public_key, public_key_hash, argument):
    hash = hash_public_key(key_type, public_key)
    if hash != public_key_hash:
        raise ex.BadPublicKeyHashException(argument, key_type, public_key, hash, public_key_hash)

def assert_non_neg(num, argument):
    if num < 0:
       raise ex.BadArgumentException(num, argument)

def assert_exhaustion(string, argument):
    if string == 'block':
        pass
    elif string == 'free_oldest':
        pass
    else:
        raise ex.BadExhaustionException(string, argument)

def assert_order(string, argument):
    if string != 'asc' and string != 'desc':
        raise ex.BadArgumentException(string, argument)

def split_access(access):
    i = access.find('/')
    if i == -1:
        return (access, None)
    else:
        return (access[0:i], access[i+1:])

def assert_access(access, argument):
    (command, args) = split_access(access)

    if command == 'allow':
        pass

    elif command == 'block':
        pass

    elif command == 'proof_of_work':
        assert_proof_of_work_args(args, argument)

    else:
        raise ex.UnknownAccessException(access, argument)

def assert_has_access(access, message_string, proof_of_work, argument):
    (command, args) = split_access(access)

    if command == 'block':
        raise ex.BlockedException()

    elif command == 'allow':
        pass

    elif command == 'proof_of_work':
        assert_proof_of_work(args, message_string, proof_of_work, argument)

    else:
        raise ex.UnknownAccessException(access, argument)


def assert_passphrase(key_type, private_key, passphrase):

    alg = crypt_all.find_alg(key_type)

    return alg.assert_passphrase(private_key, passphrase)


def sign(key_type, private_key, data, passphrase=None):

    alg = crypt_all.find_alg(key_type)

    return alg.sign(private_key, data, passphrase)


def encrypt(key_type, public_key, data):

    alg = crypt_all.find_alg(key_type)

    return alg.encrypt(public_key, data)


def decrypt(key_type, private_key, data, passphrase=None):

    alg = crypt_all.find_alg(key_type)

    return alg.decrypt(private_key, data, passphrase)


def verify_signature(key_type, public_key, data, signature):

    alg = crypt_all.find_alg(key_type)

    return alg.verify_signature(public_key, data, signature)


def assert_public_key(key_type, public_key, argument):

    alg = crypt_all.find_alg(key_type)

    alg.assert_public_key(public_key, argument)


def create_keypair(key_type, kwords):

    alg = crypt_all.find_alg(key_type)

    return alg.create_keypair(kwords)


# The methods above should be replaced by these classes.

class PublicKey:

    def __init__(self, key_type, public_key):
        self.key_type = key_type
        self.public_key_hash = hash_public_key(key_type, public_key)
        self.public_key = public_key
        self.alg = crypt_all.find_alg(key_type)

    def assert_public_key(self, argument):
        return self.alg.assert_public_key(self.public_key, argument)

    def encrypt(self, data):
        return self.alg.encrypt(self.public_key, data)

    def verify_signature(self, data, signature):
        return self.alg.verify_signature(self.public_key, data, signature)

    def assert_signature(self, data, signature, argument):
        if signature == None:
            raise ex.SignatureNullException()

        if not self.verify_signature(data, signature):
            raise ex.BadSignatureException(self.key_type, self.public_key, data, signature, argument)




class PrivateKey(PublicKey):

    def __init__(self, key_type, public_key, private_key, passphrase = None):
        PublicKey.__init__(self, key_type, public_key)
        self.private_key = private_key
        self.passphrase = passphrase

    def assert_passphrase(self):
        try:
            self.alg.assert_passphrase(self.private_key, self.passphrase)
        except ex.SimpleBadPassphraseException:
            raise ex.BadPassphraseException(self.public_key_hash)

    def decrypt(self, enc_data):
        try:
            return self.alg.decrypt(self.private_key, enc_data, self.passphrase)
        except ex.SimpleBadPassphraseException:
            raise ex.BadPassphraseException(self.public_key_hash)

    def sign(self, data):
        try:
            return self.alg.sign(self.private_key, data, self.passphrase)
        except ex.SimpleBadPassphraseException:
            raise ex.BadPassphraseException(self.public_key_hash)


def createPrivateKey(key_type, key_parameters, passphrase = None):
    alg = crypt_all.find_alg(key_type)
    (public_key, private_key) = alg.create_keypair(key_parameters)
    return PrivateKey(key_type, public_key, private_key, passphrase)




# These will be removed.
#
#def mix_token(token, data):
#    return hash_function(data + token)
#
#def verify_token(token, data, proof):
#    return mix_token(token, data) == proof
#
#def assert_token(token, data, proof, argument):
#    if proof == None:
#        raise ex.TokenNullException(argument)
#
#    if not verify_token(token, data, proof):
#        # Don't leak the token!
#        raise ex.BadTokenException(token, data, proof, argument)
#

