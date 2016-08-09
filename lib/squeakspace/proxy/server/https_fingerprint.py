# Defines a derived class of HTTPSConnection that authenticates the peer by
# verifying against an expected fingerprint of the peer certificate.

import httplib 
import hashlib

class HTTPSFingerprintException(Exception):
    def __init__(self, fingerprint_type, expected_fingerprint, peer_fingerprint):
        self.fingerprint_type = fingerprint_type
        self.expected_fingerprint = expected_fingerprint
        self.peer_fingerprint = peer_fingerprint


class HTTPSConnection_CheckFingerprint(httplib.HTTPSConnection):

    # Set fingerprint before calling connect()
    #
    # fingerprint_type = sha1|sha256
    # fingerprint is the hexdigest.
    def set_fingerprint(self, fingerprint_type, fingerprint):
        assert(fingerprint_type == 'sha1' or fingerprint_type == 'sha256')
        self.fingerprint_type = fingerprint_type
        self.fingerprint = fingerprint

    def connect(self):
        httplib.HTTPSConnection.connect(self)

        cert = self.sock.getpeercert(True) # get binary DER cert.

        if self.fingerprint_type == 'sha1':
            hash = hashlib.sha1()
        elif self.fingerprint_type == 'sha256':
            hash = hashlib.sha256()
        else:
            assert(False)

        hash.update(cert)
        peer_fingerprint = hash.hexdigest()

        if peer_fingerprint != self.fingerprint:
            raise HTTPSFingerprintException(self.fingerprint_type, self.fingerprint, peer_fingerprint)

