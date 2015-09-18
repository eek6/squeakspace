import sqlite3
import urlparse

import json
import util as ut
import session_id as sid
import squeak_cl_ex as ex
import httplib
import ssl
import config
import client

import backports.pbkdf2 as kd
import os

import base64

# show_traffic makes all proxy requests show up in the error log.
show_traffic = False

def connect(path):
    return sqlite3.connect(path)

def cursor(conn):
    return conn.cursor()

def commit(conn):
    conn.commit()

def close(conn):
    conn.close()

def make_db(c):

    c.execute('''CREATE TABLE user_passwords(user_id TEXT, params TEXT)''')

    c.execute('''CREATE TABLE public_keys (user_id TEXT, -- data owner
                                           public_key_hash TEXT,
                                           key_type TEXT,
                                           public_key TEXT,
                                           revoke_date TEXT,
                                           PRIMARY KEY(user_id, public_key_hash)) -- or null''')


    c.execute('''CREATE TABLE private_keys (user_id TEXT, -- data owner
                                            public_key_hash TEXT,
                                            key_type TEXT,
                                            public_key TEXT,
                                            private_key TEXT,
                                            revoke_date TEXT, -- or null
                                            PRIMARY KEY(user_id, public_key_hash))''')

    c.execute('''CREATE TABLE user_keys (user_id TEXT,
                                         public_key_hash TEXT) -- references private_keys''')

    c.execute('''CREATE TABLE other_user_keys (local_user_id TEXT,
                                               user_id TEXT,
                                               public_key_hash TEXT, -- reference public_keys
                                               trust_score INTEGER)''')

    c.execute('''CREATE TABLE group_keys (local_user_id TEXT, -- the user storing this here
                                          group_id TEXT,
                                          owner_id TEXT,
                                          key_use TEXT, -- post, read or delete
                                          public_key_hash TEXT); -- references private_keys''')

    c.execute('''CREATE TABLE sessions (session_id TEXT, -- not assumed to be unique.
                                        user_id TEXT PRIMARY KEY,
                                        create_time INTEGER,
                                        expire_time INTEGER)''')

    c.execute('''CREATE TABLE node_addr(user_id TEXT,
                                        node_name TEXT,
                                        url TEXT,
                                        PRIMARY KEY(user_id, node_name))''')

    c.execute('''CREATE TABLE group_access (user_id TEXT,
                                            group_id TEXT,
                                            owner_id TEXT,
                                            use TEXT,
                                            access TEXT,
                                            timestamp INTEGER,
                                            PRIMARY KEY(user_id, group_id, owner_id, use))''')

    c.execute('''CREATE TABLE message_access(user_id TEXT,
                                             to_user TEXT,
                                             from_user_key_hash TEXT,
                                             access TEXT,
                                             timestamp INTEGER,
                                             PRIMARY KEY(user_id, to_user, from_user_key_hash))''')



def make_session_id(c, user_id):

    create_time = ut.current_time()
    expire_time = create_time + config.session_expire_delay
    session_id = sid.gen_session_id(config.session_id_len)

    c.execute('''INSERT OR REPLACE INTO sessions VALUES (?, ?, ?, ?)''',
              (session_id, user_id, create_time, expire_time))

    return (session_id, create_time, expire_time)


def session_activity(c, user_id, session_id):
    curr = ut.current_time()
    new_expire_time = curr + config.session_expire_delay

    c.execute('''UPDATE sessions SET expire_time=? WHERE user_id=? AND session_id=?''',
              (new_expire_time, user_id, session_id))


def remove_expired_sessions(c):
    curr = ut.current_time()
    c.execute('''DELETE FROM sessions WHERE expire_time <= ?''', (curr,))


def assert_session_id(c, user_id, given_session_id):

    curr = ut.current_time()

    c.execute('''SELECT session_id, expire_time FROM sessions WHERE user_id=?''', (user_id,))
    row = c.fetchone()

    if row == None:
        raise ex.BadSessionIdException(user_id, given_session_id)

    (session_id, expire_time) = row

    if expire_time <= curr or given_session_id != session_id:
        raise ex.BadSessionIdException(user_id, given_session_id)


def remove_session(c, user_id, session_id):
    c.execute('''DELETE FROM sessions WHERE user_id=? AND session_id=?''',
              (user_id, session_id))


def assert_url(url):

    obj = urlparse.urlparse(url)

    if not (obj.path == '' and
            obj.params == '' and
            obj.query == '' and
            obj.fragment == '' and
            obj.username == None and
            obj.password == None and
            obj.hostname != '' and
            (obj.scheme == 'https' or obj.scheme == 'http')):

        raise ex.BadUrlException(url)


def parse_url(url):

    obj = urlparse.urlparse(url)

    assert_url(url)

    scheme = obj.scheme or 'https'
    hostname = obj.hostname
    port = obj.port or 443

    assert(scheme == 'http' or scheme == 'https')
    assert(hostname != '')

    return (scheme, hostname, port)


def load_public_key(c, user_id, public_key_hash):

    curr = ut.current_time()

    c.execute('SELECT * FROM public_keys WHERE user_id=? AND public_key_hash=?',
              (user_id, public_key_hash))
    row = c.fetchone()

    if row == None:
        raise ex.KeyNotFoundException(user_id, public_key_hash, 'public')

    (user_id, public_key_hash, key_type, public_key, revoke_date) = row

    if revoke_date != None and revoke_date <= curr:
        raise ex.KeyNotFoundException(user_id, public_key_hash, 'public')

    key = ut.PublicKey(key_type, public_key)
    assert(key.public_key_hash == public_key_hash)

    return key, revoke_date


def load_private_key(c, user_id, public_key_hash, passphrase=None):

    curr = ut.current_time()

    c.execute('SELECT * FROM private_keys WHERE user_id=? AND public_key_hash=?',
              (user_id, public_key_hash))
    row = c.fetchone()

    if row == None:
        raise ex.KeyNotFoundException(user_id, public_key_hash, 'private')

    (user_id, public_key_hash, key_type, public_key, private_key, revoke_date) = row

    if revoke_date != None and revoke_date <= curr:
        raise ex.KeyNotFoundException(user_id, public_key_hash, 'private')

    key = ut.PrivateKey(key_type, public_key, private_key, passphrase)
    assert(key.public_key_hash == public_key_hash)

    return key, revoke_date


def load_public_part_of_private_key(c, user_id, public_key_hash):

    curr = ut.current_time()

    c.execute('''SELECT key_type, public_key, revoke_date FROM private_keys
                        WHERE user_id=? AND public_key_hash=?''',
              (user_id, public_key_hash))
    row = c.fetchone()

    if row == None:
        raise ex.KeyNotFoundException(user_id, public_key_hash, 'private')

    (key_type, public_key, revoke_date) = row

    if revoke_date != None and revoke_date <= curr:
        raise ex.KeyNotFoundException(user_id, public_key_hash, 'private')

    key = ut.PublicKey(key_type, public_key)
    assert(key.public_key_hash == public_key_hash)

    return key, revoke_date


# loads the public part of a key that may be from a public key
# or the public part of a secret key.
def load_some_public_key(c, user_id, public_key_hash):

    try:
        return load_public_key(c, user_id, public_key_hash)

    except ex.KeyNotFoundException:
        return load_public_part_of_private_key(c, user_id, public_key_hash)


def load_user_key(c, user_id, public_key_hash, passphrase=None):

    c.execute('SELECT * FROM user_keys WHERE user_id=? AND public_key_hash=?',
              (user_id, public_key_hash))
    row = c.fetchone()

    if row == None:
        raise ex.UserKeyNotFoundException(user_id, public_key_hash)

    return load_private_key(c, user_id, public_key_hash, passphrase)


def load_public_user_key(c, user_id, public_key_hash):

    c.execute('SELECT * FROM user_keys WHERE user_id=? AND public_key_hash=?',
              (user_id, public_key_hash))
    row = c.fetchone()

    if row == None:
        raise ex.UserKeyNotFoundException(user_id, public_key_hash)

    return load_public_part_of_private_key(c, user_id, public_key_hash)


def load_other_user_key(c, local_user_id, user_id, public_key_hash):

    c.execute('SELECT * FROM other_user_keys WHERE local_user_id=? AND user_id=? AND public_key_hash=?',
              (local_user_id, user_id, public_key_hash))
    row = c.fetchone()

    if row == None:
        raise ex.OtherUserKeyNotFoundException(local_user_id, user_id, public_key_hash)

    (local_user_id, user_id, public_key_hash, trust_score) = row

    key, revoke_date = load_public_key(c, local_user_id, public_key_hash)

    return key, revoke_date, trust_score


def load_group_key(c, user_id, group_id, owner_id, key_use, passphrase=None):

    c.execute('''SELECT public_key_hash FROM group_keys WHERE local_user_id=?
                        AND group_id=? AND owner_id=? AND key_use=?''',
              (user_id, group_id, owner_id, key_use))
    row = c.fetchone()

    if row == None:
        #raise ex.GroupKeyNotFoundException(user_id, group_id, owner_id, key_use)
        return None, None

    (public_key_hash,) = row

    return load_private_key(c, user_id, public_key_hash, passphrase)


def load_public_group_key(c, user_id, group_id, owner_id, key_use):

    c.execute('''SELECT public_key_hash FROM group_keys WHERE local_user_id=?
                        AND group_id=? AND owner_id=? AND key_use=?''',
              (user_id, group_id, owner_id, key_use))
    row = c.fetchone()

    if row == None:
        #raise ex.GroupKeyNotFoundException(user_id, group_id, owner_id, key_use)
        return None

    (public_key_hash,) = row

    return load_public_part_of_private_key(c, user_id, public_key_hash)


def parse_proof_of_work_args(access):
    proof_of_work_str = 'proof_of_work/'

    if access == 'allow':
        return None

    elif access == 'block':
        return None

    elif access[:len(proof_of_work_str)] == proof_of_work_str:
        args = access[len(proof_of_work_str):]
        return args

    else:
        assert(False)


def load_group_proof_of_work_args(c, user_id, group_id, owner_id, use):

    access, timestamp = find_local_group_access(c, user_id, group_id, owner_id, use)

    # Assume no proof of work is needed if access is unknown.
    if access == None:
        return None

    return parse_proof_of_work_args(access)


def load_message_proof_of_work_args(c, user_id, to_user, from_user_key_hash):

    access, timestamp = find_local_message_access(c, user_id, to_user, from_user_key_hash)

    if access == None:
        return None

    return parse_proof_of_work_args(access)




## crypto requests

# local/crypt/encrypt.wsgi

def encrypt(c, user_id, session_id, public_key_hash, plaintext):

    assert_session_id(c, user_id, session_id)

    key, revoke_date = load_some_public_key(c, user_id, public_key_hash)
    ciphertext = key.encrypt(plaintext)

    return ciphertext


# local/crypt/decrypt.wsgi

def decrypt(c, user_id, session_id, public_key_hash, ciphertext, passphrase=None):
    
    assert_session_id(c, user_id, session_id)

    key, revoke_date = load_private_key(c, user_id, public_key_hash, passphrase)
    plaintext = key.decrypt(ciphertext)

    return plaintext


# local/crypt/verify_signature.wsgi

def verify_signature(c, user_id, session_id, public_key_hash, data, signature):

    assert_session_id(c, user_id, session_id)

    key, revoke_date = load_some_public_key(c, user_id, public_key_hash)
    verified = key.verify_signature(data, signature)

    return verified



# local/crypt/sign.wsgi


def sign(c, user_id, session_id, public_key_hash, data, passphrase=None):

    assert_session_id(c, user_id, session_id)

    key, revoke_date = load_private_key(c, user_id, public_key_hash, passphrase)
    signature = key.sign(data)

    return signature




## local configuration requests

# public-key.wsgi

def read_public_key(c, user_id, session_id, public_key_hash):

    assert_session_id(c, user_id, session_id)

    key, revoke_date = load_public_key(c, user_id, public_key_hash)

    return {'public_key_hash' : key.public_key_hash,
            'key_type' : key.key_type,
            'public_key' : key.public_key,
            'revoke_date' : revoke_date}


def delete_public_key(c, user_id, session_id, public_key_hash):

    assert_session_id(c, user_id, session_id)

    c.execute('DELETE FROM public_keys WHERE user_id=? AND public_key_hash=?',
              (user_id, public_key_hash))


def import_public_key(c, user_id, session_id, key_type, public_key, revoke_date):

    assert_session_id(c, user_id, session_id)

    public_key_hash = ut.hash_public_key(key_type, public_key)

    try:
        c.execute('INSERT INTO public_keys VALUES (?, ?, ?, ?, ?)',
                  (user_id, public_key_hash, key_type, public_key, revoke_date))

    except sqlite3.IntegrityError as e:
        raise ex.KeyExistsException(user_id, public_key_hash, 'public')

    return public_key_hash


# private-key.wsgi

def read_private_key(c, user_id, session_id, public_key_hash):

    assert_session_id(c, user_id, session_id)

    key, revoke_date = load_private_key(c, user_id, public_key_hash)

    return {'public_key_hash' : key.public_key_hash,
            'key_type' : key.key_type,
            'public_key' : key.public_key,
            'private_key' : key.private_key,
            'revoke_date' : revoke_date}


def delete_private_key(c, user_id, session_id, public_key_hash):

    assert_session_id(c, user_id, session_id)

    c.execute('DELETE FROM private_keys WHERE user_id=? AND public_key_hash=?',
              (user_id, public_key_hash))


def insert_private_key(c, row):
    (user_id, public_key_hash, key_type, public_key, private_key, revoke_date) = row

    try:
        c.execute('INSERT INTO private_keys VALUES (?, ?, ?, ?, ?, ?)', row)

    except sqlite3.IntegrityError:
        raise ex.KeyExistsException(user_id, public_key_hash, 'private')



def import_private_key(c, user_id, session_id, key_type, public_key, private_key, revoke_date):

    assert_session_id(c, user_id, session_id)

    public_key_hash = ut.hash_public_key(key_type, public_key)

    row = (user_id, public_key_hash, key_type, public_key, private_key, revoke_date)
    insert_private_key(c, row)

    return public_key_hash


# gen-key.wsgi

def generate_private_key(c, user_id, session_id, key_type, key_parameters, revoke_date, passphrase=None):

    assert_session_id(c, user_id, session_id)

    try:
        key_params_obj = json.loads(key_parameters)
    except ValueError:
        raise ex.BadKeyParametersException(key_parameters)

    # This might take a while. Should the connection close?
    (pub_key, priv_key) = ut.create_keypair(key_type, key_parameters)

    public_key_hash = ut.hash_public_key(key_type, pub_key)

    row = (user_id, public_key_hash, key_type, pub_key, priv_key, revoke_date)
    insert_private_key(c, row)

    return public_key_hash





# group-key.wsgi

def read_local_group_key(c, user_id, session_id, group_id, owner_id, key_use):

    assert_session_id(c, user_id, session_id)

    c.execute('SELECT * from group_keys WHERE local_user_id=? AND group_id=? AND owner_id=? AND key_use=?',
              (user_id, group_id, owner_id, key_use))
    row = c.fetchone()

    if row == None:
        raise ex.GroupKeyNotFoundException(user_id, group_id, owner_id, key_use)

    (local_user_id, group_id, owner_id, key_use, public_key_hash) = row

    return {'group_id' : group_id,
            'owner_id' : owner_id,
            'key_use' : key_use,
            'public_key_hash' : public_key_hash}


def delete_local_group_key(c, user_id, session_id, group_id, owner_id, key_use):

    assert_session_id(c, user_id, session_id)

    c.execute('DELETE FROM group_keys WHERE local_user_id=? AND group_id=? AND owner_id=? AND key_use=?',
              (user_id, group_id, owner_id, key_use))


def assign_local_group_key(c, user_id, session_id, group_id, owner_id, key_use, public_key_hash):

    assert_session_id(c, user_id, session_id)

    c.execute('SELECT public_key_hash FROM private_keys WHERE public_key_hash=?', (public_key_hash,))
    row = c.fetchone()

    if row == None:
        raise ex.PrivateKeyNotFoundException()

    try:
        c.execute('INSERT INTO group_keys VALUES (?, ?, ?, ?, ?)',
                  (user_id, group_id, owner_id, key_use, public_key_hash))

    except sqlite3.IntegrityError as e:
        raise ex.GroupKeyExistsException(user_id, group_id, owner_id, key_use)


# local/list-public-keys.wsgi

def list_public_keys(c, user_id, session_id):

    assert_session_id(c, user_id, session_id)

    key_hashes = []
    for (public_key_hash,) in c.execute('SELECT public_key_hash FROM public_keys WHERE user_id=?', (user_id,)):
        key_hashes.append(public_key_hash)

    return key_hashes

# local/list-private-keys.wsgi

def list_private_keys(c, user_id, session_id):

    assert_session_id(c, user_id, session_id)

    key_hashes = []
    for (public_key_hash,) in c.execute('SELECT public_key_hash FROM private_keys WHERE user_id=?', (user_id,)):
        key_hashes.append(public_key_hash)

    return key_hashes

# local/list-user-keys.wsgi

def list_user_keys(c, user_id, session_id):

    assert_session_id(c, user_id, session_id)

    key_hashes = []
    for (public_key_hash,) in c.execute('SELECT public_key_hash from user_keys WHERE user_id=?', (user_id,)):
        key_hashes.append(public_key_hash)

    return key_hashes


# local/list-group-keys.wsgi

def list_group_keys(c, user_id, session_id):

    assert_session_id(c, user_id, session_id)

    rows = []
    c.execute('SELECT group_id, owner_id, key_use, public_key_hash FROM group_keys WHERE local_user_id=?', (user_id,))
    for (group_id, owner_id, key_use, public_key_hash) in c:
        rows.append({'group_id' : group_id,
                     'owner_id' : owner_id,
                     'key_use' : key_use,
                     'public_key_hash' : public_key_hash})

    return rows


# local/list-other-user-keys.wsgi

def list_other_user_keys(c, user_id, session_id):

    assert_session_id(c, user_id, session_id)

    rows = []
    c.execute('SELECT user_id, public_key_hash, trust_score FROM other_user_keys WHERE local_user_id=?', (user_id,))
    for user_id, public_key_hash, trust_score in c:
        rows.append({'user_id' : user_id,
                     'public_key_hash' : public_key_hash,
                     'trust_score' : trust_score})



# local/user-key.wsgi

def read_user_key(c, user_id, session_id, public_key_hash):

    assert_session_id(c, user_id, session_id)

    c.execute('SELECT * FROM user_keys WHERE user_id=? AND public_key_hash=?',
              (user_id, public_key_hash))
    row = c.fetchone()

    if row == None:
        raise ex.UserKeyNotFoundException(user_id, public_key_hash)

    (user_id, public_key_hash) = row

    # Maybe this'll return more later.
    return {'public_key_hash' : public_key_hash}


def delete_user_key(c, user_id, session_id, public_key_hash):

    assert_session_id(c, user_id, session_id)

    c.execute('DELETE FROM user_keys WHERE user_id=? AND public_key_hash=?',
              (user_id, public_key_hash))

def assign_user_key(c, user_id, session_id, public_key_hash):

    assert_session_id(c, user_id, session_id)

    c.execute('SELECT public_key_hash FROM private_keys WHERE user_id=? AND public_key_hash=?',
              (user_id, public_key_hash))
    row = c.fetchone()

    if row == None:
        raise ex.KeyNotFoundException(user_id, public_key_hash, 'private')

    try:
        c.execute('INSERT INTO user_keys VALUES (?, ?)',
                  (user_id, public_key_hash))

    except sqlite3.IntegrityError as e:
        raise ex.UserKeyExistsException(user_id, public_key_hash)


# other-user-key.wsgi


def read_other_user_key(c, local_user_id, session_id, user_id, public_key_hash):

    assert_session_id(c, local_user_id, session_id)

    c.execute('SELECT * FROM other_user_keys WHERE local_user_id=? AND user_id=? AND public_key_hash=?',
              (local_user_id, public_key_hash))
    row = c.fetchone()

    if row == None:
        raise ex.UserKeyNotFoundException(user_id, public_key_hash)

    (local_user_id, user_id, public_key_hash, trust_score) = row

    return {'user_id' : user_id,
            'public_key_hash' : public_key_hash,
            'trust_score' : trust_score}


def delete_other_user_key(c, local_user_id, session_id, user_id, public_key_hash):

    assert_session_id(c, local_user_id, session_id)

    c.execute('DELETE FROM other_user_keys WHERE local_user_id=? AND user_id=? AND public_key_hash=?',
              (local_user_id, user_id, public_key_hash))


def assign_other_user_key(c, local_user_id, session_id, user_id, public_key_hash, trust_score):

    assert_session_id(c, local_user_id, session_id)

    c.execute('SELECT public_key_hash FROM public_keys WHERE public_key_hash=?',
              (public_key_hash,))
    row = c.fetchone()

    if row == None:
        raise ex.KeyNotFoundException(local_user_id, public_key_hash, 'public')

    c.execute('INSERT OR REPLACE INTO other_user_keys VALUES (?, ?, ?, ?)',
              (local_user_id, user_id, public_key_hash, trust_score))



# node-addr.wsgi

def get_node_addr(c, user_id, node_name):

    c.execute('SELECT url FROM node_addr WHERE user_id=? AND node_name=?',
              (user_id, node_name))
    row = c.fetchone()

    if row == None:
        raise ex.NodeAddrNotFoundException(user_id, node_name)

    (url,) = row

    return url


def get_node_connection(c, user_id, node_name):

    url = get_node_addr(c, user_id, node_name)

    (scheme, netloc, port) = parse_url(url)

    conn = None
    if scheme == 'http':
        conn = httplib.HTTPConnection(netloc, port)

    elif scheme == 'https':
        # figure out ssl certificates.
        conn = httplib.HTTPSConnection(netloc, port)

    else:
        assert(False)

    return conn, url



def read_node_addr(c, user_id, session_id, node_name):

    assert_session_id(c, user_id, session_id)

    return get_node_addr(c, user_id, node_name)


def set_node_addr(c, user_id, session_id, node_name, url):

    assert_session_id(c, user_id, session_id)

    assert_url(url)

    c.execute('INSERT OR REPLACE INTO node_addr VALUES (?, ?, ?)',
              (user_id, node_name, url))


def delete_node_addr(c, user_id, session_id, node_name):

    assert_session_id(c, user_id, session_id)

    c.execute('DELETE FROM node_addr WHERE user_id=? AND node_name=?',
              (user_id, node_name))


# local-group-access.wsgi

def find_local_group_access(c, user_id, group_id, owner_id, use):

    c.execute('''SELECT access, timestamp FROM group_access WHERE user_id=?
                        AND group_id=? AND owner_id=? AND use=?''',
              (user_id, group_id, owner_id, use))
    row = c.fetchone()

    if row == None:
        return None, None

    (access, timestamp) = row

    return access, timestamp

def load_local_group_access(c, user_id, group_id, owner_id, use):

    access, timestamp = find_local_group_access(c, user_id, group_id, owner_id, use)

    if access == None:
        raise ex.LocalGroupAccessNotFoundException(user_id, group_id, owner_id, use)

    return access, timestamp


def read_local_group_access(c, user_id, session_id, group_id, owner_id, use):

    assert_session_id(c, user_id, session_id)

    access, timestamp = load_local_group_access(c, user_id, group_id, owner_id, use)

    return {'user_id' : user_id,
            'group_id' : group_id,
            'owner_id' : owner_id,
            'use' : use,
            'access' : access,
            'timestamp' : timestamp}


def update_local_group_access(c, user_id, group_id, owner_id, use, access, timestamp = None):

    if timestamp == None:
        timestamp = ut.current_time()

    c.execute('INSERT OR REPLACE INTO group_access VALUES (?, ?, ?, ?, ?, ?)',
              (user_id, group_id, owner_id, use, access, timestamp))


def set_local_group_access(c, user_id, session_id, group_id, owner_id, use, access, timestamp = None):

    assert_session_id(c, user_id, session_id)

    update_local_group_access(c, user_id, group_id, owner_id, use, access, timestamp)


def delete_local_group_access(c, user_id, session_id, group_id, owner_id, use):

    assert_session_id(c, user_id, session_id)

    c.execute('DELETE FROM group_access WHERE user_id=? AND group_id=? AND owner_id=? AND use=?',
              (user_id, group_id, owner_id, use))


# local-message-access.wsgi

def find_local_message_access(c, user_id, to_user, from_user_key_hash):

    c.execute('''SELECT access, timestamp FROM message_access WHERE user_id=?
                        AND to_user=? AND from_user_key_hash=?''',
              (user_id, to_user, from_user_key_hash))
    row = c.fetchone()

    if row == None:
        return None, None

    (access, timestamp) = row

    return access, timestamp


def load_local_message_access(c, user_id, to_user, from_user_key_hash):

    access, timestamp = find_local_message_access(c, user_id, to_user, from_user_key_hash)

    if access == None:
        raise ex.LocalMessageAccessNotFoundException(user_id, to_user, from_user_key_hash)

    return access, timestamp


def read_local_message_access(c, user_id, session_id, to_user, from_user_key_hash):

    assert_session_id(c, user_id, session_id)

    access, timestamp = load_local_message_access(c, user_id, to_user, from_user_key_hash)

    return {'user_id' : user_id,
            'to_user' : to_user,
            'from_user_key_hash' : from_user_key_hash,
            'access' : access,
            'timestamp' : timestamp}

def update_local_message_access(c, user_id, to_user, from_user_key_hash, access, timestamp = None):

    if timestamp == None:
        timestamp = ut.current_time()

    c.execute('INSERT OR REPLACE INTO message_access VALUES (?, ?, ?, ?, ?)',
               (user_id, to_user, from_user_key_hash, access, timestamp))


def set_local_message_access(c, user_id, session_id, to_user, from_user_key_hash, access, timestamp = None):

    assert_session_id(c, user_id, session_id)

    update_local_message_access(c, user_id, to_user, from_user_key_hash, access, timestamp)


def delete_local_message_access(c, user_id, session_id, to_user, from_user_key_hash):

    assert_session_id(c, user_id, session_id)

    c.execute('DELETE FROM message_access WHERE user_id=? AND to_user=? AND from_user_key_hash=?',
              (user_id, to_user, from_user_key_hash))



# password.wsgi

def make_no_password_obj():
    return {'method' : 'no_password'}

def make_hash_password_obj(password):
    salt = base64.b64encode(os.urandom(config.pass_salt_len))
    hash = base64.b64encode(kd.pbkdf2_hmac(config.pass_hash_fun, password, salt, config.pass_rounds))
    return {'method' : 'hash',
            'hash' : hash,
            'hash_fun' : config.pass_hash_fun,
            'salt' : salt,
            'rounds' : config.pass_rounds}

def make_passphrase_password_obj(c, user_id, public_key_hash):
    c.execute('SELECT public_key, private_key FROM private_keys WHERE user_id=? AND public_key_hash=?',
              (user_id, public_key_hash))
    row = c.fetchone()
    if row == None:
        raise ex.KeyNotFoundException(user_id, public_key_hash, 'private')

    (public_key, private_key) = row

    c.execute('SELECT public_key_hash FROM user_keys WHERE user_id=? AND public_key_hash=?',
              (user_id, public_key_hash))
    row = c.fetchone()
    if row == None:
        raise ex.UserKeyNotFoundException(user_id, public_key_hash)

    return {'method' : 'passphrase', 'public_key_hash' : public_key_hash}



def set_password(c, user_id, session_id, method, password, public_key_hash):

    assert_session_id(c, user_id, session_id)

    password_obj = None

    if method == 'no_password':
        password_obj = make_no_password_obj()

    elif method == 'hash':
        password = method['password']
        password_obj = make_hash_password_obj(password)

    elif method == 'passphrase':
        public_key_hash = password_params['public_key_hash']
        password_obj = make_passphrase_password_obj(c, user_id, public_key_hash)

    else:
        ex.BadPasswordParametersException(method, password, public_key_hash)

    password_obj_str = json.dumps(password_obj)

    c.execute('INSERT OR REPLACE INTO user_passwords VALUES (?, ?)',
              (user_id, password_obj_str))


def get_password(c, user_id, session_id):

    assert_session_id(c, user_id, session_id)

    c.execute('SELECT params FROM user_passwords WHERE user_id=?', (user_id,))
    row = c.fetchone()

    if row == None:
        return None

    params_obj = json.loads(params)

    return params_obj
        

# login.wsgi

def assert_no_password():
    pass

def assert_hash_password(user_id, password, params):
    # strings come out of json as unicode.
    stored_hash = str(params['hash'])
    salt = str(params['salt'])

    hash = base64.b64encode(kd.pbkdf2_hmac(params['hash_fun'], password, salt, params['rounds']))
    if not kd.compare_digest(hash, stored_hash):
        raise ex.BadPasswordException(user_id, password)

def assert_passphrase_password(c, user_id, password, public_key_hash):
    c.execute('SELECT user_id FROM user_keys WHERE user_id=? AND public_key_hash=?',
              (user_id, public_key_hash))
    row = c.fetchone()
    assert(row != None)

    c.execute('SELECT key_type, private_key FROM private_keys WHERE user_id=? AND public_key_hash=?',
              (user_id, public_key_hash))
    row = c.fetchone()
    assert(row != None)

    (key_type, private_key) = row

    ut.assert_passphrase(key_type, private_key, passphrase)



def login(c, user_id, password):

    c.execute('SELECT params FROM user_passwords WHERE user_id=?', (user_id,))
    row = c.fetchone()

    if row == None:
        raise ex.UnregisteredUserException(user_id)

    (params,) = row

    params_obj = json.loads(params)

    method = params_obj['method']

    if method == 'no_password':
        assert_no_password()

    elif method == 'hash':
        assert_hash_password(user_id, password, params_obj)

    elif method == 'passphrase':
        public_key_hash = params_obj['public_key_hash']
        assert_passphrase_password(c, user_id, password, public_key_hash)

    else:
        assert(False)

    (session_id, create_time, expire_time) = make_session_id(c, user_id)

    return {'user_id' : user_id,
            'session_id' : session_id,
            'create_time' : create_time,
            'expire_time' : expire_time}
        

def sign_out(c, user_id, session_id):

    assert_session_id(c, user_id, session_id)

    remove_session(c, user_id, session_id)


# local/user.wsgi

# if password is None, no_password is used.
# otherwise the password is initially a hash.
# Later, the password may be set to a passphrase
# of a private key.
def create_local_user(c, user_id, password):

    params_obj = None

    if password == None:
        params_obj = make_no_password_obj()
    else:
        params_obj = make_hash_password_obj(password)

    params = json.dumps(params_obj)

    try:
        c.execute('INSERT INTO user_passwords VALUES (?, ?)',
                  (user_id, params))

    except sqlite3.IntegrityError as e:
        raise ex.LocalUserExistsException(user_id)

    (session_id, create_time, expire_time) = make_session_id(c, user_id)

    return {'user_id' : user_id,
            'session_id' : session_id,
            'create_time' : create_time,
            'expire_time' : expire_time}


def delete_local_user(c, user_id, session_id):

    assert_session_id(c, user_id, session_id)

    c.execute('DELETE FROM user_passwords WHERE user_id=?', (user_id,))
    c.execute('DELETE FROM group_keys WHERE local_user_id=?', (user_id,))
    c.execute('DELETE FROM other_user_keys WHERE local_user_id=?', (user_id,))
    c.execute('DELETE FROM user_keys WHERE user_id=?', (user_id,))
    c.execute('DELETE FROM private_keys WHERE user_id=?', (user_id,))
    c.execute('DELETE FROM public_keys WHERE user_id=?', (user_id,))
    c.execute('DELETE FROM sessions WHERE user_id=?', (user_id,))
    c.execute('DELETE FROM node_addr WHERE user_id=?', (user_id,))
    c.execute('DELETE FROM message_access WHERE user_id=?', (user_id,))
    c.execute('DELETE FROM group_access WHERE user_id=?', (user_id,))



# local/debug.wsgi

# TABLE_NAME MUST BE TRUSTED INPUT
def dump_rows(c, table_name):
    rows = []
    for row in c.execute('SELECT * FROM ' + table_name):
        rows.append(row)

    return rows


def dump_local_database(c):
    return {'user_passwords' : dump_rows(c, 'user_passwords'),
            'group_keys' : dump_rows(c, 'group_keys'),
            'other_user_keys' : dump_rows(c, 'other_user_keys'),
            'user_keys' : dump_rows(c, 'user_keys'),
            'private_keys' : dump_rows(c, 'private_keys'),
            'public_keys' : dump_rows(c, 'public_keys'),
            'sessions' : dump_rows(c, 'sessions'),
            'node_addr' : dump_rows(c, 'node_addr'),
            'message_access' : dump_rows(c, 'message_access'),
            'group_access' : dump_rows(c, 'group_access')}


# Node.
# These requests are relayed to a node after the appropriate
# cryptographic operations have been performed.

def handle_connection_exceptions(fun, args):

    try:
        return fun(*args)

    except httplib.HTTPException as e:
        raise ConnectionException(user_id, node_name, url, 'http', str(e))

    except ssl.SSLError as e:
        raise ConnectionException(user_id, node_name, url, 'ssl', str(e))

    except IOError as e:
        raise ConnectionException(user_id, node_name, url, 'socket', str(e))

# complain.wsgi

# group-access.wsgi

def change_group_access(c, user_id, session_id, node_name, group_id, use, access, public_key_hash, passphrase=None):

    assert_session_id(c, user_id, session_id)
    conn, url = get_node_connection(c, user_id, node_name)
    cl = client.Client(conn, node_name, show_traffic)
    key, revoke_date = load_user_key(c, user_id, public_key_hash, passphrase)

    return handle_connection_exceptions(
            cl.change_group_access, (group_id, user_id, use, access, key))


def read_group_access(c, user_id, session_id, node_name, group_id, owner_id, use, passphrase=None):

    assert_session_id(c, user_id, session_id)
    conn, url = get_node_connection(c, user_id, node_name)
    cl = client.Client(conn, node_name, show_traffic)
    key, revoke_date = load_group_key(c, user_id, group_id, owner_id, use, passphrase)

    resp = handle_connection_exceptions(
            cl.read_group_access, (group_id, owner_id, use, key))

    if resp['status'] == 'ok':
        update_local_group_access(c, user_id, group_id, owner_id, use, resp['access'])

    return resp


# group-key.wsgi

def change_group_key(c, user_id, session_id, node_name, group_id, key_use, group_key_hash, public_key_hash, passphrase):
    assert_session_id(c, user_id, session_id)

    pub_key = None
    if group_key_hash != None:
        pub_key, revoke_date = load_some_public_key(c, user_id, group_key_hash)

    key, revoke_date = load_user_key(c, user_id, public_key_hash, passphrase)

    conn, url = get_node_connection(c, user_id, node_name)
    cl = client.Client(conn, node_name, show_traffic)

    return handle_connection_exceptions(
            cl.change_group_key, (group_id, user_id, key_use, pub_key, key))


def read_group_key(c, user_id, session_id, node_name, group_id, key_use, public_key_hash, passphrase):
    assert_session_id(c, user_id, session_id)
    key, revoke_date = load_user_key(c, user_id, public_key_hash, passphrase)
    conn, url = get_node_connection(c, user_id, node_name)
    cl = client.Client(conn, node_name, show_traffic)

    return handle_connection_exceptions(
            cl.read_group_key, (group_id, user_id, key_use, key))


# group-config.wsgi

# group-quota.wsgi


def change_group_quota(c, user_id, session_id,
                       node_name, group_id, new_size, when_space_exhausted,
                       public_key_hash, passphrase=None):
    assert_session_id(c, user_id, session_id)
    conn, url = get_node_connection(c, user_id, node_name)
    cl = client.Client(conn, node_name, show_traffic)
    key, revoke_date = load_user_key(c, user_id, public_key_hash, passphrase)

    return handle_connection_exceptions(
            cl.change_group_quota, (group_id, user_id, new_size, when_space_exhausted, key))


def read_group_quota(c, user_id, session_id, node_name, group_id, owner_id, passphrase=None):
    assert_session_id(c, user_id, session_id)
    conn, url = get_node_connection(c, user_id, node_name)
    cl = client.Client(conn, node_name, show_traffic)
    key, revoke_date = load_group_key(c, user_id, group_id, owner_id, 'read', passphrase)
    proof_of_work_args = load_group_proof_of_work_args(c, user_id, group_id, owner_id, 'read')

    return handle_connection_exceptions(
            cl.read_group_quota, (group_id, owner_id, key, proof_of_work_args))
    

# group.wsgi

def create_group(c, user_id, session_id,
                 node_name, group_id,
                 quota_allocated, when_space_exhausted,
                 public_key_hash, passphrase=None):

    assert_session_id(c, user_id, session_id)
    conn, url = get_node_connection(c, user_id, node_name)
    cl = client.Client(conn, node_name, show_traffic)

    post_access, timestamp = load_local_group_access(c, user_id, group_id, user_id, 'post')
    read_access, timestamp = load_local_group_access(c, user_id, group_id, user_id, 'read')
    delete_access, timestamp = load_local_group_access(c, user_id, group_id, user_id, 'delete')

    posting_pub_key, posting_revoke_date = load_public_group_key(c, user_id, group_id, user_id, 'post')
    reading_pub_key, reading_revoke_date = load_public_group_key(c, user_id, group_id, user_id, 'read')
    delete_pub_key, delete_revoke_date = load_public_group_key(c, user_id, group_id, user_id, 'delete')

    key, revoke_date = load_user_key(c, user_id, public_key_hash, passphrase)

    return handle_connection_exceptions(
            cl.create_group, (group_id, user_id,
                              post_access, read_access, delete_access,
                              posting_pub_key, reading_pub_key, delete_pub_key,
                              quota_allocated, when_space_exhausted,
                              key))
 
def read_group(c, user_id, session_id, node_name, group_id, public_key_hash, passphrase=None):
    assert_session_id(c, user_id, session_id)
    conn, url = get_node_connection(c, user_id, node_name)
    cl = client.Client(conn, node_name, show_traffic)
    key, revoke_date = load_user_key(c, user_id, public_key_hash, passphrase)

    return handle_connection_exceptions(
            cl.read_group, (group_id, user_id, key))


def delete_group(c, user_id, session_id, node_name, group_id, public_key_hash, passphrase=None):
    assert_session_id(c, user_id, session_id)
    conn, url = get_node_connection(c, user_id, node_name)
    cl = client.Client(conn, node_name, show_traffic)
    key, revoke_date = load_user_key(c, user_id, public_key_hash, passphrase)

    return handle_connection_exceptions(
            cl.delete_group, (group_id, user_id, key))


# last-message-time.wsgi

def read_last_message_time(c, user_id, session_id, node_name, public_key_hash, passphrase=None):
    assert_session_id(c, user_id, session_id)
    conn, url = get_node_connection(c, user_id, node_name)
    cl = client.Client(conn, node_name, show_traffic)
    key, revoke_date = load_user_key(c, user_id, public_key_hash, passphrase)

    return handle_connection_exceptions(
            cl.read_last_message_time, (user_id, key))


# last-post-time.wsgi

def read_last_post_time(c, user_id, session_id, node_name, group_id, owner_id, passphrase=None):
    assert_session_id(c, user_id, session_id)
    conn, url = get_node_connection(c, user_id, node_name)
    cl = client.Client(conn, node_name, show_traffic)
    read_key, revoke_date = load_group_key(c, user_id, group_id, owner_id, 'read', passphrase)
    pow_args = load_group_proof_of_work_args(c, user_id, group_id, owner_id, 'read')

    return handle_connection_exceptions(
            cl.read_last_post_time, (group_id, owner_id, read_key, pow_args))


# query-message-access.wsgi

def query_message_access(c, user_id, session_id, node_name, to_user, from_user_key_hash, passphrase=None):
    assert_session_id(c, user_id, session_id)
    conn, url = get_node_connection(c, user_id, node_name)
    cl = client.Client(conn, node_name, show_traffic)
    from_key, revoke_date = load_user_key(c, user_id, from_user_key_hash, passphrase)

    return handle_connection_exceptions(
            cl.query_message_access, (to_user, user_id, from_key))



# message-access.wsgi

def read_message_access(c, user_id, session_id, node_name, from_user_key_hash, public_key_hash, passphrase=None):
    assert_session_id(c, user_id, session_id)
    conn, url = get_node_connection(c, user_id, node_name)
    cl = client.Client(conn, node_name, show_traffic)
    key, revoke_date = load_user_key(c, user_id, public_key_hash, passphrase)

    return handle_connection_exceptions(
            cl.read_message_access, (user_id, from_user_key_hash, key))


def set_message_access(c, user_id, session_id, node_name, from_user_key_hash, access, public_key_hash, passphrase=None):
    assert_session_id(c, user_id, session_id)
    conn, url = get_node_connection(c, user_id, node_name)
    cl = client.Client(conn, node_name, show_traffic)
    key, revoke_date = load_user_key(c, user_id, public_key_hash, passphrase)

    return handle_connection_exceptions(
            cl.set_message_access, (user_id, from_user_key_hash, access, key))


def delete_message_access(c, user_id, session_id, node_name, from_user_key_hash, public_key_hash, passphrase=None):
    assert_session_id(c, user_id, session_id)
    conn, url = get_node_connection(c, user_id, node_name)
    cl = client.Client(conn, node_name, show_traffic)
    key, revoke_date = load_user_key(c, user_id, public_key_hash, passphrase)

    return handle_connection_exceptions(
            cl.delete_message_access, (user_id, from_user_key_hash, key))


# message-list.wsgi


def read_message_list(c, user_id, session_id,
                      node_name, start_time, end_time, max_records, order,
                      public_key_hash, passphrase = None):
    assert_session_id(c, user_id, session_id)
    conn, url = get_node_connection(c, user_id, node_name)
    cl = client.Client(conn, node_name, show_traffic)
    key, revoke_date = load_user_key(c, user_id, public_key_hash, passphrase)

    return handle_connection_exceptions(
            cl.read_message_list, (user_id, start_time, end_time, max_records, order, key))



# message-quota.wsgi

def change_message_quota(c, user_id, session_id,
                         node_name, new_size, when_space_exhausted,
                         public_key_hash, passphrase=None):
    assert_session_id(c, user_id, session_id)
    conn, url = get_node_connection(c, user_id, node_name)
    cl = client.Client(conn, node_name, show_traffic)
    key, revoke_date = load_user_key(c, user_id, public_key_hash, passphrase)

    return handle_connection_exceptions(
            cl.change_message_quota, (user_id, new_size, when_space_exhausted, key))

def read_message_quota(c, user_id, session_id, node_name, public_key_hash, passphrase=None):
    assert_session_id(c, user_id, session_id)
    conn, url = get_node_connection(c, user_id, node_name)
    cl = client.Client(conn, node_name, show_traffic)
    key, revoke_date = load_user_key(c, user_id, public_key_hash, passphrase)

    return handle_connection_exceptions(
            cl.read_message_quota, (user_id, key))

# message.wsgi

def read_message(c, user_id, session_id, node_name, message_id, public_key_hash, passphrase=None):
    assert_session_id(c, user_id, session_id)
    conn, url = get_node_connection(c, user_id, node_name)
    cl = client.Client(conn, node_name, show_traffic)
    key, revoke_date = load_user_key(c, user_id, public_key_hash, passphrase)

    return handle_connection_exceptions(
            cl.read_message, (user_id, message_id, key))


def send_message(c, user_id, session_id,
                 node_name, to_user, to_user_key_hash, from_user_key_hash,
                 message, passphrase=None):
    assert_session_id(c, user_id, session_id)
    conn, url = get_node_connection(c, user_id, node_name)
    cl = client.Client(conn, node_name, show_traffic)

    from_user = None
    from_key = None
    revoke_date = None

    if from_user_key_hash != None:
        from_user = user_id
        from_key, revoke_date = load_user_key(c, user_id, from_user_key_hash, passphrase)

    pow_args = load_message_proof_of_work_args(c, user_id, to_user, from_user_key_hash)

    return handle_connection_exceptions(
            cl.send_message, (to_user, to_user_key_hash, from_user, from_key, message, pow_args))


def delete_message(c, user_id, session_id, node_name, message_id, public_key_hash, passphrase=None):
    assert_session_id(c, user_id, session_id)
    conn, url = get_node_connection(c, user_id, node_name)
    cl = client.Client(conn, node_name, show_traffic)
    key, revoke_date = load_user_key(c, user_id, public_key_hash, passphrase)

    return handle_connection_exceptions(
            cl.delete_message, (user_id, message_id, key))

# node.wsgi

# post-list.wsgi

def read_post_list(c, user_id, session_id,
                   node_name, group_id, owner_id,
                   start_time, end_time, max_records, order, passphrase=None):
    assert_session_id(c, user_id, session_id)
    conn, url = get_node_connection(c, user_id, node_name)
    cl = client.Client(conn, node_name, show_traffic)
    read_key, revoke_date = load_group_key(c, user_id, group_id, owner_id, 'read', passphrase)
    pow_args = load_group_proof_of_work_args(c, user_id, group_id, owner_id, 'read')

    return handle_connection_exceptions(
            cl.read_post_list, (group_id, owner_id,
                                start_time, end_time, max_records, order,
                                read_key, pow_args))
 

# post.wsgi


def make_post(c, user_id, session_id, node_name, group_id, owner_id, data, passphrase=None):
    assert_session_id(c, user_id, session_id)
    conn, url = get_node_connection(c, user_id, node_name)
    cl = client.Client(conn, node_name, show_traffic)
    post_key, revoke_date = load_group_key(c, user_id, group_id, owner_id, 'post', passphrase)
    pow_args = load_group_proof_of_work_args(c, user_id, group_id, owner_id, 'post')

    return handle_connection_exceptions(
            cl.make_post, (group_id, owner_id, data, post_key, pow_args))
    

def read_post(c, user_id, session_id, node_name, group_id, owner_id, post_id, passphrase=None):
    assert_session_id(c, user_id, session_id)
    conn, url = get_node_connection(c, user_id, node_name)
    cl = client.Client(conn, node_name, show_traffic)
    read_key, revoke_date = load_group_key(c, user_id, group_id, owner_id, 'read', passphrase)
    pow_args = load_group_proof_of_work_args(c, user_id, group_id, owner_id, 'read')

    return handle_connection_exceptions(
            cl.read_post, (group_id, owner_id, post_id, read_key, pow_args))


def delete_post(c, user_id, session_id, node_name, group_id, owner_id, post_id, passphrase=None):
    assert_session_id(c, user_id, session_id)
    conn, url = get_node_connection(c, user_id, node_name)
    cl = client.Client(conn, node_name, show_traffic)
    delete_key, revoke_date = load_group_key(c, user_id, group_id, owner_id, 'delete', passphrase)
    pow_args = load_group_proof_of_work_args(c, user_id, group_id, owner_id, 'delete')

    return handle_connection_exceptions(
            cl.delete_post, (group_id, owner_id, post_id, delete_key, pow_args))


# user-quota.wsgi


def change_user_quota(c, user_id, session_id,
                      node_name, new_size, user_class, auth_token,
                      public_key_hash, passphrase=None):
    assert_session_id(c, user_id, session_id)
    conn, url = get_node_connection(c, user_id, node_name)
    cl = client.Client(conn, node_name, show_traffic)
    key, revoke_date = load_user_key(c, user_id, public_key_hash, passphrase)

    return handle_connection_exceptions(
            cl.change_user_quota, (user_id, new_size, user_class, auth_token, key))


def read_user_quota(c, user_id, session_id, node_name, public_key_hash, passphrase=None):
    assert_session_id(c, user_id, session_id)
    conn, url = get_node_connection(c, user_id, node_name)
    cl = client.Client(conn, node_name, show_traffic)
    key, revoke_date = load_user_key(c, user_id, public_key_hash, passphrase)

    return handle_connection_exceptions(
            cl.read_user_quota, (user_id, key))



# proxy/user.wsgi


def create_user(c, user_id, session_id,
                node_name, public_key_hash,
                default_message_access, when_mail_exhausted,
                quota_size, mail_quota_size,
                user_class, auth_token):
    assert_session_id(c, user_id, session_id)
    conn, url = get_node_connection(c, user_id, node_name)
    cl = client.Client(conn, node_name, show_traffic)
    pub_key, revoke_date = load_public_user_key(c, user_id, public_key_hash)

    return handle_connection_exceptions(
            cl.create_user, (user_id, pub_key, revoke_date,
                             default_message_access, when_mail_exhausted,
                             quota_size, mail_quota_size,
                             user_class, auth_token))


def read_user(c, user_id, session_id, node_name, public_key_hash, passphrase=None):
    assert_session_id(c, user_id, session_id)
    conn, url = get_node_connection(c, user_id, node_name)
    cl = client.Client(conn, node_name, show_traffic)
    key, revoke_date = load_user_key(c, user_id, public_key_hash, passphrase)

    return handle_connection_exceptions(
            cl.read_user, (user_id, key))


def delete_user(c, user_id, session_id, node_name, public_key_hash, passphrase=None):
    assert_session_id(c, user_id, session_id)
    conn, url = get_node_connection(c, user_id, node_name)
    cl = client.Client(conn, node_name, show_traffic)
    key, revoke_date = load_user_key(c, user_id, public_key_hash, passphrase)

    return handle_connection_exceptions(
            cl.delete_user, (user_id, key))

# proxy/version.wsgi

def read_version(c, user_id, session_id, node_name):
    assert_session_id(c, user_id, session_id)
    conn, url = get_node_connection(c, user_id, node_name)
    cl = client.Client(conn, node_name, show_traffic)

    return handle_connection_exceptions(
            cl.read_version, ())


