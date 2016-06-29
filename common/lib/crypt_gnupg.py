

import json
import os
import squeak_ex as ex

import gnupg


# public keys are json arrays.
# [fingerprint, key]



#def debug_print(*args):
#    print args

def debug_print(*args):
    pass


# When an operation is performed, the key is loaded into the key ring,
# used, and then removed from the key ring. There is only one
# key allowed in the key ring at a time and it is removed
# after it's done being used. See the note under decrypt().

class CryptGnuPG:
    standard = "pgp"
    name = "gnupg"

    def __init__(self, path_root, gpg=None, sig_file_path=None):
        try:
            os.makedirs(path_root)
        except OSError:
            pass

        if gpg == None:
            gpg = gnupg.GPG(homedir = path_root + '/gnupg')
        if sig_file_path == None:
            sig_file_path = path_root + '/sig_file'

        self.gpg = gpg
        self.sig_file_path = sig_file_path

    
    def assert_single_key(self, fingerprint):
        keys = self.gpg.list_keys()
        debug_print ('assert_single_key', keys)
        debug_print ('assert_single_key len', len(keys))
        assert(len(keys) == 1)
        debug_print ('assert_single_key fingerprint', keys[0]['fingerprint'], fingerprint)
        assert(keys[0]['fingerprint'] == fingerprint)
    
    def assert_public_key(self, public_key, argument):
        debug_print ('assert_public_key', public_key, argument)
        key_obj = json.loads(public_key)
        debug_print ('assert_public_key key_obj', key_obj)
        assert(type(key_obj) == list)
        assert(len(key_obj) == 2)
        fingerprint = key_obj[0]
        key_str = key_obj[1]

        debug_print ('assert_public_key fingerprint', fingerprint)
        debug_print ('assert_public_key key_str', key_str)
    
        temp = self.gpg.import_keys(key_str)
        debug_print ('assert_public_key import_keys', temp.results)
        assert(len(temp.results) == 1)
        assert(temp.results[0]['status'] == 'Entirely new key\n')
        assert(temp.results[0]['fingerprint'] == fingerprint)
    
        temp = self.gpg.export_keys(fingerprint)
        debug_print ('assert_public_key export_keys', temp)
        assert(temp == key_str)
    
        self.assert_single_key(fingerprint)
    
        temp = self.gpg.delete_keys(fingerprint)
        debug_print ('assert_public_key delete_keys', temp.status)
        assert(temp.status == 'ok')
    
    def assert_passphrase(self, private_key, passphrase=None):
        assert(False)
    
    def encrypt(self, public_key, data):
        debug_print('encrypt', public_key, data)
        key_obj = json.loads(public_key)
        debug_print('encrypt key_obj', key_obj)
        assert(type(key_obj) == list)
        assert(len(key_obj) == 2)
        fingerprint = key_obj[0]
        key_str = key_obj[1]
        debug_print('encrypt fingerprint', fingerprint)
        debug_print('encrypt key_str', key_str)
    
        temp = self.gpg.import_keys(key_str)
        debug_print('encrypt import_keys', temp.results)
        assert(len(temp.results) == 1)
        assert(temp.results[0]['status'] == 'Entirely new key\n')
        assert(temp.results[0]['fingerprint'] == fingerprint)
    
        temp = self.gpg.export_keys(fingerprint)
        debug_print('encrypt export_keys', temp)
        assert(temp == key_str)
    
        self.assert_single_key(fingerprint)
    
        temp = self.gpg.encrypt(data, fingerprint)
        debug_print('encrypt encrypt', temp.status, temp.ok)
        assert(temp.ok)
    
        enc = str(temp)
    
        temp = self.gpg.delete_keys(fingerprint)
        debug_print('encrypt delete_keys', temp.status)
        assert(temp.status == 'ok')
    
        return enc
    
    # private key is the json encoded array [fingerprint, entire_key]
    def decrypt(self, private_key, data, passphrase=None):
        debug_print('decrypt', private_key, data, passphrase)
        key_obj = json.loads(private_key)
        debug_print('decrypt key_obj', key_obj)
        assert(type(key_obj) == list)
        assert(len(key_obj) == 2)
        fingerprint = key_obj[0]
        key_str = key_obj[1]
        debug_print('decrypt fingerprint', fingerprint)
        debug_print('decrypt key_str', key_str)
    
        temp = self.gpg.import_keys(key_str)
        debug_print('decrypt import_keys', temp.results)
        assert(len(temp.results) == 2)
        assert(temp.results[0]['status'] == 'Contains private key\n')
        assert(temp.results[0]['fingerprint'] == fingerprint)
        assert(temp.results[1]['status'] == 'Entirely new key\n')
        assert(temp.results[1]['fingerprint'] == fingerprint)

        try:
    
            temp = self.gpg.export_keys(fingerprint, secret=True)
            debug_print('decrypt export_keys', temp)
            assert(temp == key_str)
        
            self.assert_single_key(fingerprint)
        
            temp = self.gpg.decrypt(data, passphrase=passphrase)
            debug_print('decrypt decrypt', temp.status, temp.ok)
            if not temp.ok:
                # Make this more robust!
                # Actually check if the failure is due to the passphrase.
                raise ex.SimpleBadPassphraseException()
        
            dec = str(temp)
            return dec
        
        finally:

            temp = self.gpg.delete_keys(fingerprint, secret=True)
            debug_print('decrypt delete_keys(secret)', temp.status)
            assert(temp.status == 'ok')
        
            temp = self.gpg.delete_keys(fingerprint)
            debug_print('decrypt delete_keys', temp.status)
            assert(temp.status == 'ok')
    
    
    def sign(self, private_key, data, passphrase=None):

        debug_print('sign', private_key, data, passphrase)
        key_obj = json.loads(private_key)
        debug_print('sign key_obj', key_obj)
        assert(type(key_obj) == list)
        assert(len(key_obj) == 2)
        fingerprint = key_obj[0]
        key_str = key_obj[1]
        debug_print('sign fingerprint', fingerprint)
        debug_print('sign key_str', key_str)
    
        temp = self.gpg.import_keys(key_str)
        debug_print('sign import_keys', temp.results)
        assert(len(temp.results) == 2)
        assert(temp.results[0]['status'] == 'Contains private key\n')
        assert(temp.results[0]['fingerprint'] == fingerprint)
        assert(temp.results[1]['status'] == 'Entirely new key\n')
        assert(temp.results[1]['fingerprint'] == fingerprint)

        try:
        
            temp = self.gpg.export_keys(fingerprint, secret=True)
            debug_print('sign export_keys', temp)
            assert(temp == key_str)
        
            self.assert_single_key(fingerprint)
        
            temp = self.gpg.sign(data,
                    default_key=fingerprint,
                    detach=True,
                    clearsign=False,
                    binary=False,
                    passphrase=passphrase)
        
            debug_print('sign sign', temp.status, temp.fingerprint)
            #assert(temp.fingerprint == fingerprint) # this is a fingerprint of a subkey?
            if temp.status != 'begin signing':
                # Make this more robust!
                # It could have failed for some other reason.
                raise ex.SimpleBadPassphraseException()
        
            sig = str(temp)
            return sig
    
        finally:
        
            temp = self.gpg.delete_keys(fingerprint, secret=True)
            debug_print('sign delete_keys(secret)', temp.status)
            assert(temp.status == 'ok')
        
            temp = self.gpg.delete_keys(fingerprint)
            debug_print('sign delete_keys', temp.status)
            assert(temp.status == 'ok')
    
    
    def verify_signature(self, public_key, data, signature):
        debug_print('verify_signature', public_key, data, signature)
        key_obj = json.loads(public_key)
        debug_print('verify_signature key_obj', key_obj)
        assert(type(key_obj) == list)
        assert(len(key_obj) == 2)
        fingerprint = key_obj[0]
        key_str = key_obj[1]
        debug_print('verify_signature fingerprint', fingerprint)
        debug_print('verify_signature key_str', key_str)
    
        sig_file = open(self.sig_file_path, "w")
    
        try:
            sig_file.write(signature)
            sig_file.close()
        
            temp = self.gpg.import_keys(key_str)
            debug_print('verify_signature import_keys', temp.results)
            assert(len(temp.results) == 1)
            assert(temp.results[0]['status'] == 'Entirely new key\n')
            assert(temp.results[0]['fingerprint'] == fingerprint)
        
            temp = self.gpg.export_keys(fingerprint)
            debug_print('verify_signature export_key', temp)
            assert(temp == key_str)
        
            self.assert_single_key(fingerprint)
        
            temp = self.gpg.verify_file(data, self.sig_file_path)
            debug_print('verify_signature verify_file', temp.status, temp.fingerprint)

            valid = (temp.status == 'signature valid')
            #assert(temp.fingerprint == fingerprint) # must be subkey fingerprint or something.

            temp = self.gpg.delete_keys(fingerprint)
            debug_print ('verify_signature delete_keys.status', temp.status)
            assert(temp.status == 'ok')

            return valid
    
        finally:
            os.remove(self.sig_file_path)
    
    # See keywords for gnupg.GPG.gen_key_input()
    # for possible values in params.
    def create_keypair(self, kwords):
        debug_print ('create_keypair', kwords)
        key_input = self.gpg.gen_key_input(**kwords)
    
        key = self.gpg.gen_key(key_input)
        debug_print ('create_keypair key.status', key.status)
        assert(key.status == 'key created')
    
        fingerprint = str(key)
        debug_print ('create_keypair fingerprint', fingerprint)

        public_key_str = self.gpg.export_keys(fingerprint)
        debug_print ('create_keypair public_key_str', public_key_str)

        private_key_str = self.gpg.export_keys(fingerprint, secret=True)
        debug_print ('create_keypair private_key_str', private_key_str)
    
        public_key = json.dumps([fingerprint, public_key_str])
        debug_print ('create_keypair public_key', public_key)

        private_key = json.dumps([fingerprint, private_key_str])
        debug_print ('create_keypair private_key', private_key)
    
        temp = self.gpg.delete_keys(fingerprint, secret=True)
        debug_print ('create_keypair delete_keys(secret).status', temp.status)
        assert(temp.status == 'ok')
    
        temp = self.gpg.delete_keys(fingerprint)
        debug_print ('create_keypair delete_keys.status', temp.status)
        assert(temp.status == 'ok')
    
        return (public_key, private_key)
