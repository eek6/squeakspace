import sqlite3
import urlparse

import json
import util as ut
import session_id as sid
import squeak_cl_ex as ex
import squeak_ex as common_ex
import httplib
import ssl
import config
import client
import passphrase_cache

import backports.pbkdf2 as kd
import os

import base64

# show_traffic makes all proxy requests show up in the error log.
show_traffic = False

pass_cache = passphrase_cache.PassphraseCache()

def get_required_parameter(object, key, object_name):
    try:
        return object[key]
    except KeyError:
        raise ex.RespParamRequiredException(key, object_name)

def connect(path):
    return sqlite3.connect(path)

def cursor(conn):
    return conn.cursor()

def commit(conn):
    conn.commit()

def close(conn):
    conn.close()

def make_db(c):

    c.execute('''CREATE TABLE user_passwords(user_id TEXT, params TEXT, PRIMARY KEY(user_id))''')

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
                                         node_name TEXT, -- OR NULL
                                         public_key_hash TEXT,
                                         PRIMARY KEY(user_id, node_name, public_key_hash)) -- references private_keys''')

    c.execute('''CREATE TABLE other_user_keys (local_user_id TEXT,
                                               user_id TEXT,
                                               node_name TEXT,
                                               public_key_hash TEXT, -- reference public_keys
                                               trust_score INTEGER,
                                               PRIMARY KEY(local_user_id, user_id, node_name, public_key_hash))''')

    c.execute('''CREATE TABLE group_keys (local_user_id TEXT, -- the user storing this here
                                          group_id TEXT,
                                          owner_id TEXT,
                                          node_name TEXT,
                                          key_use TEXT, -- post, read or delete
                                          public_key_hash TEXT, -- references private_keys
                                          PRIMARY KEY(local_user_id, group_id, owner_id, node_name, key_use))''')

    c.execute('''CREATE TABLE sessions (session_id TEXT, -- not assumed to be unique.
                                        user_id TEXT PRIMARY KEY,
                                        create_time INTEGER,
                                        expire_time INTEGER)''')

    c.execute('''CREATE TABLE node_addr(user_id TEXT,
                                        node_name TEXT,
                                        url TEXT,
                                        real_node_name TEXT,
                                        PRIMARY KEY(user_id, node_name))''')

    c.execute('''CREATE TABLE group_access (user_id TEXT,
                                            group_id TEXT,
                                            owner_id TEXT,
                                            node_name TEXT,
                                            use TEXT,
                                            access TEXT,
                                            timestamp INTEGER,
                                            PRIMARY KEY(user_id, group_id, owner_id, node_name, use))''')

    c.execute('''CREATE TABLE message_access(user_id TEXT,
                                             to_user TEXT,
                                             node_name TEXT,
                                             from_user_key_hash TEXT,
                                             access TEXT,
                                             timestamp INTEGER,
                                             PRIMARY KEY(user_id, to_user, node_name, from_user_key_hash))''')

    c.execute('''CREATE TABLE default_message_access(user_id TEXT,
                                                     to_user TEXT,
                                                     node_name TEXT,
                                                     access TEXT,
                                                     timestamp INTEGER,
                                                     PRIMARY KEY(user_id, to_user, node_name))''')





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

    if passphrase == None:
        passphrase = pass_cache.get_passphrase(user_id, public_key_hash)

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


def load_user_key(c, user_id, node_name, public_key_hash, passphrase=None):

    c.execute('SELECT * FROM user_keys WHERE user_id=? AND node_name=? AND public_key_hash=?',
              (user_id, node_name, public_key_hash))
    row = c.fetchone()

    if row == None:
        raise ex.UserKeyNotFoundException(user_id, node_name, public_key_hash)

    return load_private_key(c, user_id, public_key_hash, passphrase)


def load_public_user_key(c, user_id, node_name, public_key_hash):

    c.execute('SELECT * FROM user_keys WHERE user_id=? AND node_name=? AND public_key_hash=?',
              (user_id, node_name, public_key_hash))
    row = c.fetchone()

    if row == None:
        raise ex.UserKeyNotFoundException(user_id, node_name, public_key_hash)

    return load_public_part_of_private_key(c, user_id, public_key_hash)


def load_other_user_key(c, local_user_id, user_id, node_name, public_key_hash):

    c.execute('SELECT * FROM other_user_keys WHERE local_user_id=? AND user_id=? AND node_name=? AND public_key_hash=?',
              (local_user_id, user_id, node_name, public_key_hash))
    row = c.fetchone()

    if row == None:
        raise ex.OtherUserKeyNotFoundException(local_user_id, user_id, node_name, public_key_hash)

    (local_user_id, user_id, node_name, public_key_hash, trust_score) = row

    key, revoke_date = load_public_key(c, local_user_id, public_key_hash)

    return key, revoke_date, trust_score


def load_group_key(c, user_id, group_id, owner_id, node_name, key_use, passphrase=None):

    c.execute('''SELECT public_key_hash FROM group_keys WHERE local_user_id=?
                        AND group_id=? AND owner_id=? AND node_name=? AND key_use=?''',
              (user_id, group_id, owner_id, node_name, key_use))
    row = c.fetchone()

    if row == None:
        #raise ex.GroupKeyNotFoundException(user_id, group_id, owner_id, node_name, key_use)
        return None, None

    (public_key_hash,) = row

    return load_private_key(c, user_id, public_key_hash, passphrase)


def load_public_group_key(c, user_id, group_id, owner_id, node_name, key_use):

    c.execute('''SELECT public_key_hash FROM group_keys WHERE local_user_id=?
                        AND group_id=? AND owner_id=? AND node_name=? AND key_use=?''',
              (user_id, group_id, owner_id, node_name, key_use))
    row = c.fetchone()

    if row == None:
        #raise ex.GroupKeyNotFoundException(user_id, group_id, owner_id, node_name, key_use)
        return None, None

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


def load_group_proof_of_work_args(c, user_id, group_id, owner_id, node_name, use):

    access, timestamp = find_local_group_access(c, user_id, group_id, owner_id, node_name, use)

    # Assume no proof of work is needed if access is unknown.
    if access == None:
        return None

    return parse_proof_of_work_args(access)


def load_message_proof_of_work_args(c, user_id, to_user, node_name, from_user_key_hash):

    access, timestamp = find_local_message_access(c, user_id, to_user, node_name, from_user_key_hash)

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

    plaintext = None

    try:
        plaintext = key.decrypt(ciphertext)
    except common_ex.SimpleBadPassphraseException:
        raise common_ex.BadPassphraseException(public_key_hash)

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

    signature = None

    try:
        signature = key.sign(data)
    except common_ex.SimpleBadPassphraseException:
        raise common_ex.BadPassphraseException(public_key_hash)

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
    except TypeError:
        raise ex.BadKeyParametersException(key_parameters)

    # This might take a while. Should the connection close?
    #(pub_key, priv_key) = ut.create_keypair(key_type, key_parameters)
    (pub_key, priv_key) = ut.create_keypair(key_type, key_params_obj)

    public_key_hash = ut.hash_public_key(key_type, pub_key)

    row = (user_id, public_key_hash, key_type, pub_key, priv_key, revoke_date)
    insert_private_key(c, row)

    return public_key_hash





# group-key.wsgi

def read_local_group_key(c, user_id, session_id, group_id, owner_id, node_name, key_use):

    assert_session_id(c, user_id, session_id)

    c.execute('SELECT * from group_keys WHERE local_user_id=? AND group_id=? AND owner_id=? AND node_name=? AND key_use=?',
              (user_id, group_id, owner_id, node_name, key_use))
    row = c.fetchone()

    if row == None:
        raise ex.GroupKeyNotFoundException(user_id, group_id, owner_id, node_name, key_use)

    (local_user_id, group_id, owner_id, node_name, key_use, public_key_hash) = row

    return {'group_id' : group_id,
            'owner_id' : owner_id,
            'node_name' : node_name,
            'key_use' : key_use,
            'public_key_hash' : public_key_hash}


def delete_local_group_key(c, user_id, session_id, group_id, owner_id, node_name, key_use):

    assert_session_id(c, user_id, session_id)

    c.execute('DELETE FROM group_keys WHERE local_user_id=? AND group_id=? AND owner_id=? AND node_name=? AND key_use=?',
              (user_id, group_id, owner_id, node_name, key_use))


def assign_local_group_key(c, user_id, session_id, group_id, owner_id, node_name, key_use, public_key_hash):

    assert_session_id(c, user_id, session_id)

    c.execute('SELECT public_key_hash FROM private_keys WHERE public_key_hash=?', (public_key_hash,))
    row = c.fetchone()

    if row == None:
        raise ex.PrivateKeyNotFoundException()

    c.execute('INSERT OR REPLACE INTO group_keys VALUES (?, ?, ?, ?, ?, ?)',
              (user_id, group_id, owner_id, node_name, key_use, public_key_hash))


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

def list_user_keys(c, user_id, session_id, node_name):

    assert_session_id(c, user_id, session_id)

    if node_name == None:
        c.execute('SELECT node_name, public_key_hash from user_keys WHERE user_id=?', (user_id,))
    else:
        c.execute('SELECT node_name, public_key_hash from user_keys WHERE user_id=? AND node_name=?',
                  (user_id, node_name))

    keys = []
    for node_name, public_key_hash in c:
        keys.append({'node_name' : node_name,
                     'public_key_hash' : public_key_hash})

    return keys


# local/list-group-keys.wsgi

def list_group_keys(c, user_id, session_id):

    assert_session_id(c, user_id, session_id)

    rows = []
    c.execute('SELECT group_id, owner_id, node_name, key_use, public_key_hash FROM group_keys WHERE local_user_id=?', (user_id,))
    for (group_id, owner_id, node_name, key_use, public_key_hash) in c:
        rows.append({'group_id' : group_id,
                     'owner_id' : owner_id,
                     'node_name' : node_name,
                     'key_use' : key_use,
                     'public_key_hash' : public_key_hash})

    return rows


# local/list-other-user-keys.wsgi

def list_other_user_keys(c, user_id, session_id, other_user_id=None, node_name=None):

    assert_session_id(c, user_id, session_id)

    rows = []

    query = 'SELECT user_id, node_name, public_key_hash, trust_score FROM other_user_keys WHERE local_user_id=?'
    args = [user_id]

    if other_user_id != None:
        query += ' AND user_id=?'
        args.append(other_user_id)

    if node_name != None:
        query += ' AND node_name=?'
        args.append(node_name)


    #c.execute('SELECT user_id, node_name, public_key_hash, trust_score FROM other_user_keys WHERE local_user_id=?', (user_id,))
    c.execute(query, args)

    for user_id, node_name, public_key_hash, trust_score in c:
        rows.append({'user_id' : user_id,
                     'node_name' : node_name,
                     'public_key_hash' : public_key_hash,
                     'trust_score' : trust_score})

    return rows



# local/user-key.wsgi

def read_user_key(c, user_id, session_id, node_name, public_key_hash):

    assert_session_id(c, user_id, session_id)

    c.execute('SELECT * FROM user_keys WHERE user_id=? AND node_name=? AND public_key_hash=?',
              (user_id, node_name, public_key_hash))
    row = c.fetchone()

    if row == None:
        raise ex.UserKeyNotFoundException(user_id, node_name, public_key_hash)

    (user_id, node_name, public_key_hash) = row

    # Maybe this'll return more later.
    return {'node_name' : node_name,
            'public_key_hash' : public_key_hash}


def delete_user_key(c, user_id, session_id, node_name, public_key_hash):

    assert_session_id(c, user_id, session_id)

    c.execute('DELETE FROM user_keys WHERE user_id=? AND node_name=? AND public_key_hash=?',
              (user_id, node_name, public_key_hash))

def assign_user_key(c, user_id, session_id, node_name, public_key_hash):

    assert_session_id(c, user_id, session_id)

    c.execute('SELECT public_key_hash FROM private_keys WHERE user_id=? AND public_key_hash=?',
              (user_id, public_key_hash))
    row = c.fetchone()

    if row == None:
        raise ex.KeyNotFoundException(user_id, public_key_hash, 'private')

    try:
        c.execute('INSERT INTO user_keys VALUES (?, ?, ?)',
                  (user_id, node_name, public_key_hash))

    except sqlite3.IntegrityError as e:
        raise ex.UserKeyExistsException(user_id, node_name, public_key_hash)


# other-user-key.wsgi


def read_other_user_key(c, local_user_id, session_id, user_id, node_name, public_key_hash):

    assert_session_id(c, local_user_id, session_id)

    c.execute('SELECT * FROM other_user_keys WHERE local_user_id=? AND user_id=? AND node_name=? AND public_key_hash=?',
              (local_user_id, user_id, node_name, public_key_hash))
    row = c.fetchone()

    if row == None:
        raise ex.UserKeyNotFoundException(user_id, public_key_hash)

    (local_user_id, user_id, node_name, public_key_hash, trust_score) = row

    return {'user_id' : user_id,
            'node_name' : node_name,
            'public_key_hash' : public_key_hash,
            'trust_score' : trust_score}


def delete_other_user_key(c, local_user_id, session_id, user_id, node_name, public_key_hash):

    assert_session_id(c, local_user_id, session_id)

    c.execute('DELETE FROM other_user_keys WHERE local_user_id=? AND user_id=? AND node_name=? AND public_key_hash=?',
              (local_user_id, user_id, node_name, public_key_hash))


def assign_other_user_key(c, local_user_id, session_id, user_id, node_name, public_key_hash, trust_score):

    assert_session_id(c, local_user_id, session_id)

    c.execute('SELECT public_key_hash FROM public_keys WHERE public_key_hash=?',
              (public_key_hash,))
    row = c.fetchone()

    if row == None:
        raise ex.KeyNotFoundException(local_user_id, public_key_hash, 'public')

    c.execute('INSERT OR REPLACE INTO other_user_keys VALUES (?, ?, ?, ?, ?)',
              (local_user_id, user_id, node_name, public_key_hash, trust_score))



# node-addr.wsgi

def get_node_addr(c, user_id, node_name):

    c.execute('SELECT url, real_node_name FROM node_addr WHERE user_id=? AND node_name=?',
              (user_id, node_name))
    row = c.fetchone()

    if row == None:
        raise ex.NodeAddrNotFoundException(user_id, node_name)

    (url, real_node_name) = row

    return url, real_node_name


def get_node_connection(c, user_id, node_name):

    url, real_node_name = get_node_addr(c, user_id, node_name)

    (scheme, netloc, port) = parse_url(url)

    conn = None
    if scheme == 'http':
        conn = httplib.HTTPConnection(netloc, port)

    elif scheme == 'https':
        # figure out ssl certificates.
        # this is important.
        conn = httplib.HTTPSConnection(netloc, port)

    else:
        assert(False)

    return conn, url, real_node_name



def read_node_addr(c, user_id, session_id, node_name):

    assert_session_id(c, user_id, session_id)

    url, real_node_name = get_node_addr(c, user_id, node_name)

    return {'node_name' : node_name,
            'url' : url,
            'real_node_name' : real_node_name}


def set_node_addr(c, user_id, session_id, node_name, url, real_node_name):

    assert_session_id(c, user_id, session_id)

    assert_url(url)

    c.execute('INSERT OR REPLACE INTO node_addr VALUES (?, ?, ?, ?)',
              (user_id, node_name, url, real_node_name))


def delete_node_addr(c, user_id, session_id, node_name):

    assert_session_id(c, user_id, session_id)

    c.execute('DELETE FROM node_addr WHERE user_id=? AND node_name=?',
              (user_id, node_name))


# local-list-node-addr.wsi

def list_node_addr(c, user_id, session_id):

    assert_session_id(c, user_id, session_id)

    rows = []
    for row in c.execute('SELECT node_name, url, real_node_name FROM node_addr WHERE user_id=?', (user_id,)):
        (node_name, url, real_node_name) = row
        rows.append({'node_name': node_name,
                     'url': url,
                     'real_node_name': real_node_name})

    return rows
        

# local-group-access.wsgi

def find_local_group_access(c, user_id, group_id, owner_id, node_name, use):

    c.execute('''SELECT access, timestamp FROM group_access WHERE user_id=?
                        AND group_id=? AND owner_id=? AND node_name=? AND use=?''',
              (user_id, group_id, owner_id, node_name, use))
    row = c.fetchone()

    if row == None:
        return None, None

    (access, timestamp) = row

    return access, timestamp

def load_local_group_access(c, user_id, group_id, owner_id, node_name, use):

    access, timestamp = find_local_group_access(c, user_id, group_id, owner_id, node_name, use)

    if access == None:
        raise ex.LocalGroupAccessNotFoundException(user_id, group_id, owner_id, node_name, use)

    return access, timestamp


def read_local_group_access(c, user_id, session_id, group_id, owner_id, node_name, use):

    assert_session_id(c, user_id, session_id)

    access, timestamp = load_local_group_access(c, user_id, group_id, owner_id, node_name, use)

    return {'user_id' : user_id,
            'group_id' : group_id,
            'owner_id' : owner_id,
            'node_name' : node_name,
            'use' : use,
            'access' : access,
            'timestamp' : timestamp}


def update_local_group_access(c, user_id, group_id, owner_id, node_name, use, access, timestamp = None):

    if timestamp == None:
        timestamp = ut.current_time()

    c.execute('INSERT OR REPLACE INTO group_access VALUES (?, ?, ?, ?, ?, ?, ?)',
              (user_id, group_id, owner_id, node_name, use, access, timestamp))



def set_local_group_access(c, user_id, session_id, group_id, owner_id, node_name, use, access, timestamp = None):

    assert_session_id(c, user_id, session_id)

    update_local_group_access(c, user_id, group_id, owner_id, node_name, use, access, timestamp)


def delete_local_group_access(c, user_id, session_id, group_id, owner_id, node_name, use):

    assert_session_id(c, user_id, session_id)

    c.execute('DELETE FROM group_access WHERE user_id=? AND group_id=? AND owner_id=? AND node_name=? AND use=?',
              (user_id, group_id, owner_id, node_name, use))


# default-message-access routines.

def set_local_default_message_access(c, user_id, to_user, node_name, access, timestamp = None):

    # print ('set_local_default_message_access', user_id, to_user, node_name, access, timestamp)

    if timestamp == None:
        timestamp = ut.current_time()

    c.execute('INSERT OR REPLACE INTO default_message_access VALUES (?, ?, ?, ?, ?)',
              (user_id, to_user, node_name, access, timestamp))

def delete_local_default_message_access(c, user_id, to_user, node_name):
    c.execute('DELETE FROM default_message_access WHERE user_id=? AND to_user=? AND node_name=?',
              (user_id, to_user, node_name))

def find_local_default_message_access(c, user_id, to_user, node_name):

    c.execute('SELECT access, timestamp from default_message_access WHERE user_id=? AND to_user=? AND node_name=?',
              (user_id, to_user, node_name))
    row = c.fetchone()

    if row == None:
        return None, None

    (access, timestamp) = row

    return access, timestamp


def load_local_default_message_access(c, user_id, to_user, node_name):

    access, timestamp = find_local_default_message_access(c, user_id, to_user, node_name)

    if access == None:
        raise ex.LocalDefaultMessageAccessNotFoundException(user_id, to_user, node_name)

    return access, timestamp


# local-message-access.wsgi

def find_local_message_access_(c, user_id, to_user, node_name, from_user_key_hash):
    
    # print ('find_local_message_access:', ('user_id', user_id), ('to_user', to_user), ('node_name', node_name), ('from_user_key_hash', from_user_key_hash))

    c.execute('''SELECT access, timestamp FROM message_access WHERE user_id=?
                        AND to_user=? AND node_name=? AND from_user_key_hash=?''',
              (user_id, to_user, node_name, from_user_key_hash))

    row = c.fetchone()

    if row == None:
        return None, None

    (access, timestamp) = row

    return access, timestamp


def load_local_message_access_(c, user_id, to_user, node_name, from_user_key_hash):

    access, timestamp = find_local_message_access(c, user_id, to_user, node_name, from_user_key_hash)

    if access == None:
        raise ex.LocalMessageAccessNotFoundException(user_id, to_user, node_name, from_user_key_hash)

    return access, timestamp


def find_local_message_access(c, user_id, to_user, node_name, from_user_key_hash):
    if from_user_key_hash == None:
        return find_local_default_message_access(c, user_id, to_user, node_name)
    else:
        return find_local_message_access_(c, user_id, to_user, node_name, from_user_key_hash)


def load_local_message_access(c, user_id, to_user, node_name, from_user_key_hash):
    if from_user_key_hash == None:
        return load_local_default_message_access(c, user_id, to_user, node_name)
    else:
        access, timestamp = find_local_message_access(c, user_id, to_user, node_name, from_user_key_hash)

        if access == None:
            return load_local_default_message_access(c, user_id, to_user, node_name)

        return access, timestamp


def read_local_message_access(c, user_id, session_id, to_user, node_name, from_user_key_hash):

    assert_session_id(c, user_id, session_id)

    access, timestamp = load_local_message_access(c, user_id, to_user, node_name, from_user_key_hash)

    return {'user_id' : user_id,
            'to_user' : to_user,
            'node_name' : node_name,
            'from_user_key_hash' : from_user_key_hash,
            'access' : access,
            'timestamp' : timestamp}

def update_local_message_access_(c, user_id, to_user, node_name, from_user_key_hash, access, timestamp = None):

    # print ('update_local_message_access_', user_id, to_user, node_name, from_user_key_hash, access, timestamp)

    assert(from_user_key_hash != None)

    if timestamp == None:
        timestamp = ut.current_time()

    c.execute('INSERT OR REPLACE INTO message_access VALUES (?, ?, ?, ?, ?, ?)',
               (user_id, to_user, node_name, from_user_key_hash, access, timestamp))

def debug_local_message_access(c, user_id):
    return c.execute('SELECT * FROM message_access WHERE user_id=?', (user_id,)).fetchall()


def update_local_message_access(c, user_id, to_user, node_name, from_user_key_hash, access, timestamp = None):

    # print ('update_local_message_access', user_id, to_user, node_name, from_user_key_hash, access, timestamp)

    if timestamp == None:
        timestamp = ut.current_time()

    if from_user_key_hash == None:
        set_local_default_message_access(c, user_id, to_user, node_name, access, timestamp)
    else:
        update_local_message_access_(c, user_id, to_user, node_name, from_user_key_hash, access, timestamp)

    access_, timestamp_ = load_local_message_access(c, user_id, to_user, node_name, from_user_key_hash)
    assert(access_ == access)
    assert(timestamp_ == timestamp)


def delete_raw_local_message_access(c, user_id, to_user, node_name, from_user_key_hash):
    c.execute('DELETE FROM message_access WHERE user_id=? AND to_user=? AND node_name=? AND from_user_key_hash=?',
              (user_id, to_user, node_name, from_user_key_hash))


def set_local_message_access(c, user_id, session_id, to_user, node_name, from_user_key_hash, access, timestamp = None):

    assert_session_id(c, user_id, session_id)

    update_local_message_access(c, user_id, to_user, node_name, from_user_key_hash, access, timestamp)


def delete_local_message_access(c, user_id, session_id, to_user, node_name, from_user_key_hash):

    assert_session_id(c, user_id, session_id)

    if from_user_key_hash == None:
        delete_local_default_message_access(c, user_id, to_user, node_name)
    else:
        delete_raw_local_message_access(c, user_id, to_user, node_name, from_user_key_hash)


# passphrase.wsgi

def cache_passphrase(c, user_id, session_id, public_key_hash, passphrase, expire_time):

    assert_session_id(c, user_id, session_id)

    pass_cache.set(user_id, public_key_hash, passphrase, expire_time)


def delete_passphrase(c, user_id, session_id, public_key_hash):

    assert_session_id(c, user_id, session_id)

    if public_key_hash != None:
        pass_cache.delete(user_id, public_key_hash)
    else:
        pass_cache.purge_user(user_id)


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
        # raise ex.UnregisteredUserException(user_id)
        # report bad password so people can't probe for user accounts.
        raise ex.BadPasswordException(user_id, password)

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

    pass_cache.purge_user(user_id)

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
    c.execute('DELETE FROM default_message_access WHERE user_id=?', (user_id,))
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
    conn, url, real_node_name = get_node_connection(c, user_id, node_name)
    cl = client.Client(conn, real_node_name, show_traffic)
    key, revoke_date = load_user_key(c, user_id, node_name, public_key_hash, passphrase)

    return handle_connection_exceptions(
            cl.change_group_access, (group_id, user_id, use, access, key))


def read_group_access(c, user_id, session_id, node_name, group_id, owner_id, use, passphrase=None):

    assert_session_id(c, user_id, session_id)
    conn, url, real_node_name = get_node_connection(c, user_id, node_name)
    cl = client.Client(conn, real_node_name, show_traffic)
    key, revoke_date = load_group_key(c, user_id, group_id, owner_id, node_name, use, passphrase)

    resp = handle_connection_exceptions(
            cl.read_group_access, (group_id, owner_id, use, key))

    if resp['status'] == 'ok':
        update_local_group_access(c, user_id, group_id, owner_id, node_name, use, resp['access'])

    return resp


# group-key.wsgi

def change_group_key(c, user_id, session_id, node_name, group_id, key_use, group_key_hash, public_key_hash, passphrase):
    assert_session_id(c, user_id, session_id)

    pub_key = None
    if group_key_hash != None:
        pub_key, revoke_date = load_some_public_key(c, user_id, group_key_hash)

    key, revoke_date = load_user_key(c, user_id, node_name, public_key_hash, passphrase)

    conn, url, real_node_name = get_node_connection(c, user_id, node_name)
    cl = client.Client(conn, real_node_name, show_traffic)

    return handle_connection_exceptions(
            cl.change_group_key, (group_id, user_id, key_use, pub_key, key))


def read_group_key(c, user_id, session_id, node_name, group_id, key_use, public_key_hash, passphrase):
    assert_session_id(c, user_id, session_id)
    key, revoke_date = load_user_key(c, user_id, node_name, public_key_hash, passphrase)
    conn, url, real_node_name = get_node_connection(c, user_id, node_name)
    cl = client.Client(conn, real_node_name, show_traffic)

    return handle_connection_exceptions(
            cl.read_group_key, (group_id, user_id, key_use, key))



# group-config.wsgi

# group-quota.wsgi


def change_group_quota(c, user_id, session_id,
                       node_name, group_id, new_size, when_space_exhausted,
                       public_key_hash, passphrase=None):
    assert_session_id(c, user_id, session_id)
    conn, url, real_node_name = get_node_connection(c, user_id, node_name)
    cl = client.Client(conn, real_node_name, show_traffic)
    key, revoke_date = load_user_key(c, user_id, node_name, public_key_hash, passphrase)

    return handle_connection_exceptions(
            cl.change_group_quota, (group_id, user_id, new_size, when_space_exhausted, key))


def read_group_quota(c, user_id, session_id, node_name, group_id, owner_id, passphrase=None):
    assert_session_id(c, user_id, session_id)
    conn, url, real_node_name = get_node_connection(c, user_id, node_name)
    cl = client.Client(conn, real_node_name, show_traffic)
    key, revoke_date = load_group_key(c, user_id, group_id, owner_id, node_name, 'read', passphrase)
    proof_of_work_args = load_group_proof_of_work_args(c, user_id, group_id, owner_id, node_name, 'read')

    return handle_connection_exceptions(
            cl.read_group_quota, (group_id, owner_id, key, proof_of_work_args))
    

# group.wsgi

def create_group(c, user_id, session_id,
                 node_name, group_id,
                 quota_allocated, when_space_exhausted,
                 public_key_hash, passphrase=None):

    assert_session_id(c, user_id, session_id)
    conn, url, real_node_name = get_node_connection(c, user_id, node_name)
    cl = client.Client(conn, real_node_name, show_traffic)

    post_access, timestamp = load_local_group_access(c, user_id, group_id, user_id, node_name, 'post')
    read_access, timestamp = load_local_group_access(c, user_id, group_id, user_id, node_name, 'read')
    delete_access, timestamp = load_local_group_access(c, user_id, group_id, user_id, node_name, 'delete')

    posting_pub_key, posting_revoke_date = load_public_group_key(c, user_id, group_id, user_id, node_name, 'post')
    reading_pub_key, reading_revoke_date = load_public_group_key(c, user_id, group_id, user_id, node_name, 'read')
    delete_pub_key, delete_revoke_date = load_public_group_key(c, user_id, group_id, user_id, node_name, 'delete')

    key, revoke_date = load_user_key(c, user_id, node_name, public_key_hash, passphrase)

    return handle_connection_exceptions(
            cl.create_group, (group_id, user_id,
                              post_access, read_access, delete_access,
                              posting_pub_key, reading_pub_key, delete_pub_key,
                              quota_allocated, when_space_exhausted,
                              key))
 
def read_group(c, user_id, session_id, node_name, group_id, public_key_hash, passphrase=None):
    assert_session_id(c, user_id, session_id)
    conn, url, real_node_name = get_node_connection(c, user_id, node_name)
    cl = client.Client(conn, real_node_name, show_traffic)
    key, revoke_date = load_user_key(c, user_id, node_name, public_key_hash, passphrase)

    return handle_connection_exceptions(
            cl.read_group, (group_id, user_id, key))


def delete_group(c, user_id, session_id, node_name, group_id, public_key_hash, passphrase=None):
    assert_session_id(c, user_id, session_id)
    conn, url, real_node_name = get_node_connection(c, user_id, node_name)
    cl = client.Client(conn, real_node_name, show_traffic)
    key, revoke_date = load_user_key(c, user_id, node_name, public_key_hash, passphrase)

    return handle_connection_exceptions(
            cl.delete_group, (group_id, user_id, key))


# last-message-time.wsgi

def read_last_message_time(c, user_id, session_id, node_name, public_key_hash, passphrase=None):
    assert_session_id(c, user_id, session_id)
    conn, url, real_node_name = get_node_connection(c, user_id, node_name)
    cl = client.Client(conn, real_node_name, show_traffic)
    key, revoke_date = load_user_key(c, user_id, node_name, public_key_hash, passphrase)

    return handle_connection_exceptions(
            cl.read_last_message_time, (user_id, key))


# last-post-time.wsgi

def read_last_post_time(c, user_id, session_id, node_name, group_id, owner_id, passphrase=None):
    assert_session_id(c, user_id, session_id)
    conn, url, real_node_name = get_node_connection(c, user_id, node_name)
    cl = client.Client(conn, real_node_name, show_traffic)
    read_key, revoke_date = load_group_key(c, user_id, group_id, owner_id, node_name, 'read', passphrase)
    pow_args = load_group_proof_of_work_args(c, user_id, group_id, owner_id, node_name, 'read')

    return handle_connection_exceptions(
            cl.read_last_post_time, (group_id, owner_id, read_key, pow_args))


# query-message-access.wsgi

def query_message_access(c, user_id, session_id, node_name, to_user, from_user_key_hash, passphrase=None):
    assert_session_id(c, user_id, session_id)
    conn, url, real_node_name = get_node_connection(c, user_id, node_name)
    cl = client.Client(conn, real_node_name, show_traffic)
    from_key = None
    if from_user_key_hash != None:
        from_key, revoke_date = load_user_key(c, user_id, node_name, from_user_key_hash, passphrase)

    resp = handle_connection_exceptions(
            cl.query_message_access, (to_user, user_id, from_key))

    # print ('local.query_message_access.resp', resp)

    if resp['status'] == 'ok':
        message_access = resp['message_access'] # todo: handle KeyError
        access = message_access['access']
        # print ('local.query_message_access.update_local_message_access', user_id, to_user, node_name, from_user_key_hash, access)
        update_local_message_access(c, user_id, to_user, node_name, from_user_key_hash, access)

        #debug = debug_local_message_access(c, user_id)
        #print ('query_message_access. local. after get', debug)
        #assert(len(debug) > 0)

    return resp



# message-access.wsgi

def read_message_access(c, user_id, session_id, node_name, from_user_key_hash, public_key_hash, passphrase=None):
    assert_session_id(c, user_id, session_id)
    conn, url, real_node_name = get_node_connection(c, user_id, node_name)
    cl = client.Client(conn, real_node_name, show_traffic)
    key, revoke_date = load_user_key(c, user_id, node_name, public_key_hash, passphrase)

    resp = handle_connection_exceptions(
            cl.read_message_access, (user_id, from_user_key_hash, key))

    if resp['status'] == 'ok':
        access = resp['access']
        update_local_message_access(c, user_id, user_id, node_name, from_user_key_hash, access)

    return resp


def set_message_access(c, user_id, session_id, node_name, from_user_key_hash, access, public_key_hash, passphrase=None):

    # print ('set_message_access', user_id, session_id, node_name, from_user_key_hash, access, public_key_hash, passphrase)

    assert_session_id(c, user_id, session_id)
    conn, url, real_node_name = get_node_connection(c, user_id, node_name)
    cl = client.Client(conn, real_node_name, show_traffic)
    key, revoke_date = load_user_key(c, user_id, node_name, public_key_hash, passphrase)

    resp = handle_connection_exceptions(
            cl.set_message_access, (user_id, from_user_key_hash, access, key))

    # print ('set_message_access.resp', resp)

    if resp['status'] == 'ok':
        # print ('set_message_access.resp.status ok')
        update_local_message_access(c, user_id, user_id, node_name, from_user_key_hash, access)

    return resp


def delete_message_access(c, user_id, session_id, node_name, from_user_key_hash, public_key_hash, passphrase=None):
    assert_session_id(c, user_id, session_id)
    conn, url, real_node_name = get_node_connection(c, user_id, node_name)
    cl = client.Client(conn, real_node_name, show_traffic)
    key, revoke_date = load_user_key(c, user_id, node_name, public_key_hash, passphrase)

    resp = handle_connection_exceptions(
            cl.delete_message_access, (user_id, from_user_key_hash, key))

    if resp['status'] == 'ok':
        if from_user_key_hash != None:
            delete_raw_local_message_access(c, user_id, user_id, node_name, from_user_key_hash)
        else:
            delete_local_default_message_access(c, user_id, user_id, node_name);

    return resp




# message-list.wsgi


def read_message_list(c, user_id, session_id,
                      node_name, start_time, end_time, max_records, order,
                      public_key_hash, passphrase = None):
    assert_session_id(c, user_id, session_id)
    conn, url, real_node_name = get_node_connection(c, user_id, node_name)
    cl = client.Client(conn, real_node_name, show_traffic)
    key, revoke_date = load_user_key(c, user_id, node_name, public_key_hash, passphrase)

    return handle_connection_exceptions(
            cl.read_message_list, (user_id, start_time, end_time, max_records, order, key))



# message-quota.wsgi

def change_message_quota(c, user_id, session_id,
                         node_name, new_size, when_space_exhausted,
                         public_key_hash, passphrase=None):
    assert_session_id(c, user_id, session_id)
    conn, url, real_node_name = get_node_connection(c, user_id, node_name)
    cl = client.Client(conn, real_node_name, show_traffic)
    key, revoke_date = load_user_key(c, user_id, node_name, public_key_hash, passphrase)

    return handle_connection_exceptions(
            cl.change_message_quota, (user_id, new_size, when_space_exhausted, key))

def read_message_quota(c, user_id, session_id, node_name, public_key_hash, passphrase=None):
    assert_session_id(c, user_id, session_id)
    conn, url, real_node_name = get_node_connection(c, user_id, node_name)
    cl = client.Client(conn, real_node_name, show_traffic)
    key, revoke_date = load_user_key(c, user_id, node_name, public_key_hash, passphrase)

    return handle_connection_exceptions(
            cl.read_message_quota, (user_id, key))


# message validation

def validate_message(c, user_id, session_id, node_name, real_node_name,
        message_id, timestamp, to_user_key_hash,
        from_user, from_user_key_hash,
        message, message_hash,
        from_signature, proof_of_work):

    assert_session_id(c, user_id, session_id)

    ut.assert_hash(message, message_hash, 'message_hash')

    validate_message_header(c, user_id, session_id, node_name, real_node_name,
            message_id, timestamp, to_user_key_hash,
            from_user, from_user_key_hash,
            message_hash,
            from_signature, proof_of_work)


def validate_message_header(c, user_id, session_id, node_name, real_node_name,
        message_id, timestamp, to_user_key_hash,
        from_user, from_user_key_hash,
        message_hash,
        from_signature, proof_of_work):

    assert_session_id(c, user_id, session_id)

    message_id_string = ut.serialize_request(
            ['SEND_MESSAGE', timestamp, real_node_name,
             user_id, to_user_key_hash,
             from_user, from_user_key_hash,
             message_hash])
    ut.assert_hash(message_id_string, message_id, 'message_id')

    if to_user_key_hash != None:
        to_key, revoke_date = load_public_part_of_private_key(c, user_id, to_user_key_hash)

    if from_user_key_hash != None:
        from_key, revoke_date, trust_score = load_other_user_key(c, user_id, from_user, node_name, from_user_key_hash)
        from_key.assert_signature(message_id, from_signature, 'from_signature')

    access, timestamp = load_local_message_access(c, user_id, user_id, node_name, from_user_key_hash)
    ut.assert_has_access(access, message_id, proof_of_work, 'message_id')
 


# message.wsgi

def read_message(c, user_id, session_id, node_name, message_id,
                 public_key_hash, passphrase=None,
                 to_key_passphrase=None, decrypt_message=None):

    if decrypt_message == None:
        decrypt_message = True

    assert_session_id(c, user_id, session_id)
    conn, url, real_node_name = get_node_connection(c, user_id, node_name)
    cl = client.Client(conn, real_node_name, show_traffic)
    key, revoke_date = load_user_key(c, user_id, node_name, public_key_hash, passphrase)

    resp = handle_connection_exceptions(
            cl.read_message, (user_id, message_id, key))

    if resp['status'] != 'ok':
        return resp, None

    validation = None

    try:
        message_obj = get_required_parameter(resp, 'message', 'resp')

        message = get_required_parameter(message_obj, 'message', 'resp.message')
        message_id = get_required_parameter(message_obj, 'message_id', 'resp.message')
        timestamp = get_required_parameter(message_obj, 'timestamp', 'resp.message')
        to_user = get_required_parameter(message_obj, 'to_user', 'resp.message')
        to_user_key_hash = get_required_parameter(message_obj, 'to_user_key', 'resp.message')
        from_user = get_required_parameter(message_obj, 'from_user', 'resp.message')
        from_user_key_hash = get_required_parameter(message_obj, 'from_user_key', 'resp.message')
        message_hash = get_required_parameter(message_obj, 'message_hash', 'resp.message')
        from_signature = get_required_parameter(message_obj, 'from_signature', 'resp.message')
        proof_of_work = get_required_parameter(message_obj, 'proof_of_work', 'resp.message')

        if to_user != user_id:
            return resp, {'status': 'error',
                          'reason': 'to_user does not match user_id',
                          'to_user': to_user,
                          'user_id': user_id}

        validate_message(c, user_id, session_id, node_name, real_node_name,
                message_id, timestamp, to_user_key_hash,
                from_user, from_user_key_hash,
                message, message_hash,
                from_signature, proof_of_work)

        validation = {'status' : 'ok'}

    except common_ex.SqueakException as e:
        validation = e.dict()
        #return resp, validation

    message_obj = get_required_parameter(resp, 'message', 'resp')
    to_user_key_hash = get_required_parameter(message_obj, 'to_user_key', 'resp.message')

    if decrypt_message == True and to_user_key_hash != None:
        message = get_required_parameter(message_obj, 'message', 'resp.message')

        to_key, revoke_date = load_user_key(c, user_id, node_name, to_user_key_hash, to_key_passphrase)
        plaintext = to_key.decrypt(message)
        message_obj['message'] = plaintext

    return resp, validation



def send_message(c, user_id, session_id,
                 node_name, to_user, to_user_key_hash, from_user_key_hash,
                 message, passphrase=None, force_encryption=None):

    if force_encryption == None:
        force_encryption = True

    assert_session_id(c, user_id, session_id)
    conn, url, real_node_name = get_node_connection(c, user_id, node_name)
    cl = client.Client(conn, real_node_name, show_traffic)

    from_user = None
    from_key = None

    if from_user_key_hash != None:
        from_user = user_id
        from_key, revoke_date = load_user_key(c, user_id, node_name, from_user_key_hash, passphrase)

    pow_args = load_message_proof_of_work_args(c, user_id, to_user, node_name, from_user_key_hash)

    public_message = None

    if to_user_key_hash != None:
        to_user_pub_key, revoke_date, trust_score = load_other_user_key(c, user_id, to_user, node_name, to_user_key_hash)
        public_message = to_user_pub_key.encrypt(message)
    elif force_encryption == True:
        raise ex.EncryptionForcedException('to_user_key_hash')
    else:
        public_message = message


    return handle_connection_exceptions(
            cl.send_message, (to_user, to_user_key_hash, from_user, from_key, public_message, pow_args))


def delete_message(c, user_id, session_id, node_name, message_id, public_key_hash, passphrase=None):
    assert_session_id(c, user_id, session_id)
    conn, url, real_node_name = get_node_connection(c, user_id, node_name)
    cl = client.Client(conn, real_node_name, show_traffic)
    key, revoke_date = load_user_key(c, user_id, node_name, public_key_hash, passphrase)

    return handle_connection_exceptions(
            cl.delete_message, (user_id, message_id, key))

# node.wsgi

# post-list.wsgi

def read_post_list(c, user_id, session_id,
                   node_name, group_id, owner_id,
                   start_time, end_time, max_records, order, passphrase=None):
    assert_session_id(c, user_id, session_id)
    conn, url, real_node_name = get_node_connection(c, user_id, node_name)
    cl = client.Client(conn, real_node_name, show_traffic)
    read_key, revoke_date = load_group_key(c, user_id, group_id, owner_id, node_name, 'read', passphrase)
    pow_args = load_group_proof_of_work_args(c, user_id, group_id, owner_id, node_name, 'read')

    return handle_connection_exceptions(
            cl.read_post_list, (group_id, owner_id,
                                start_time, end_time, max_records, order,
                                read_key, pow_args))
 

# post.wsgi


def make_post(c, user_id, session_id, node_name, group_id, owner_id, data,
              passphrase=None, force_encryption=None):

    if force_encryption == None:
        force_encryption = True

    assert_session_id(c, user_id, session_id)
    conn, url, real_node_name = get_node_connection(c, user_id, node_name)
    cl = client.Client(conn, real_node_name, show_traffic)
    post_key, revoke_date = load_group_key(c, user_id, group_id, owner_id, node_name, 'post', passphrase)
    pow_args = load_group_proof_of_work_args(c, user_id, group_id, owner_id, node_name, 'post')

    read_pub_key, revoke_date2 = load_public_group_key(c, user_id, group_id, owner_id, node_name, 'read')

    public_data = None

    if read_pub_key != None:
        public_data = read_pub_key.encrypt(data)
    elif force_encryption == True:
        raise ex.EncryptionForcedException('read key missing')
    else:
        public_data = data

    return handle_connection_exceptions(
            cl.make_post, (group_id, owner_id, public_data, post_key, pow_args))
    

def read_post(c, user_id, session_id, node_name, group_id, owner_id, post_id, passphrase=None, decrypt_post=None):

    if decrypt_post == None:
        decrypt_post = True

    assert_session_id(c, user_id, session_id)
    conn, url, real_node_name = get_node_connection(c, user_id, node_name)
    cl = client.Client(conn, real_node_name, show_traffic)
    read_key, revoke_date = load_group_key(c, user_id, group_id, owner_id, node_name, 'read', passphrase)
    pow_args = load_group_proof_of_work_args(c, user_id, group_id, owner_id, node_name, 'read')

    resp = handle_connection_exceptions(
            cl.read_post, (group_id, owner_id, post_id, read_key, pow_args))

    if resp['status'] != 'ok':
        return resp

    if decrypt_post == True and read_key != None:
        post = get_required_parameter(resp, 'post', 'resp')
        data = get_required_parameter(post, 'data', 'resp.post')
        plaintext = read_key.decrypt(data)
        post['data'] = plaintext

    return resp


def delete_post(c, user_id, session_id, node_name, group_id, owner_id, post_id, passphrase=None):
    assert_session_id(c, user_id, session_id)
    conn, url, real_node_name = get_node_connection(c, user_id, node_name)
    cl = client.Client(conn, real_node_name, show_traffic)
    delete_key, revoke_date = load_group_key(c, user_id, group_id, owner_id, node_name, 'delete', passphrase)
    pow_args = load_group_proof_of_work_args(c, user_id, group_id, owner_id, node_name, 'delete')

    return handle_connection_exceptions(
            cl.delete_post, (group_id, owner_id, post_id, delete_key, pow_args))


# user-quota.wsgi


def change_user_quota(c, user_id, session_id,
                      node_name, new_size, user_class, auth_token,
                      public_key_hash, passphrase=None):
    assert_session_id(c, user_id, session_id)
    conn, url, real_node_name = get_node_connection(c, user_id, node_name)
    cl = client.Client(conn, real_node_name, show_traffic)
    key, revoke_date = load_user_key(c, user_id, node_name, public_key_hash, passphrase)

    return handle_connection_exceptions(
            cl.change_user_quota, (user_id, new_size, user_class, auth_token, key))


def read_user_quota(c, user_id, session_id, node_name, public_key_hash, passphrase=None):
    assert_session_id(c, user_id, session_id)
    conn, url, real_node_name = get_node_connection(c, user_id, node_name)
    cl = client.Client(conn, real_node_name, show_traffic)
    key, revoke_date = load_user_key(c, user_id, node_name, public_key_hash, passphrase)

    return handle_connection_exceptions(
            cl.read_user_quota, (user_id, key))



# proxy/user.wsgi


def create_user(c, user_id, session_id,
                node_name, public_key_hash,
                default_message_access, when_mail_exhausted,
                quota_size, mail_quota_size,
                user_class, auth_token):
    assert_session_id(c, user_id, session_id)
    conn, url, real_node_name = get_node_connection(c, user_id, node_name)
    cl = client.Client(conn, real_node_name, show_traffic)
    pub_key, revoke_date = load_public_user_key(c, user_id, node_name, public_key_hash)

    resp = handle_connection_exceptions(
            cl.create_user, (user_id, pub_key, revoke_date,
                             default_message_access, when_mail_exhausted,
                             quota_size, mail_quota_size,
                             user_class, auth_token))

    set_local_default_message_access(c, user_id, user_id, node_name, default_message_access)

    return resp


def read_user(c, user_id, session_id, node_name, public_key_hash, passphrase=None):
    assert_session_id(c, user_id, session_id)
    conn, url, real_node_name = get_node_connection(c, user_id, node_name)
    cl = client.Client(conn, real_node_name, show_traffic)
    key, revoke_date = load_user_key(c, user_id, node_name, public_key_hash, passphrase)

    return handle_connection_exceptions(
            cl.read_user, (user_id, key))


def delete_user(c, user_id, session_id, node_name, public_key_hash, passphrase=None):
    assert_session_id(c, user_id, session_id)
    conn, url, real_node_name = get_node_connection(c, user_id, node_name)
    cl = client.Client(conn, real_node_name, show_traffic)
    key, revoke_date = load_user_key(c, user_id, node_name, public_key_hash, passphrase)

    resp = handle_connection_exceptions(
            cl.delete_user, (user_id, key))

    return resp

# proxy/version.wsgi

def read_version(c, user_id, session_id, node_name):
    assert_session_id(c, user_id, session_id)
    conn, url, real_node_name = get_node_connection(c, user_id, node_name)
    cl = client.Client(conn, real_node_name, show_traffic)

    return handle_connection_exceptions(
            cl.read_version, ())


