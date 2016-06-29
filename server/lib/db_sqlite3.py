import sqlite3

import config_proto
import config
import squeak_ex as ex
import util as ut


def connect(path):
    return sqlite3.connect(path)

def cursor(conn):
    return conn.cursor()

def commit(conn):
    conn.commit()

def close(conn):
    conn.close()

root_quota_id = 1




def assert_timestamp_fresh(timestamp, argument):
    ut.assert_timestamp_fresh(
            timestamp, argument,
            config.acceptable_future, config.acceptable_delay)


def make_db(c, total_quota):
    c.execute('''CREATE TABLE keys 
                 (identity TEXT,
                  identity_type TEXT, -- node or user
                  key_type TEXT,
                  public_key TEXT,
                  public_key_hash TEXT,
                  revoke_date INTEGER,
                  trust_score INTEGER,
                  download_source TEXT)''')

    # This is where the node stores its keys.
    # Move this to a different database.
    c.execute('''CREATE TABLE priv_keys
                 (identity TEXT,
                  identity_type TEXT,
                  public_key_hash TEXT,
                  public_key TEXT,
                  private_key TEXT)''')

    c.execute('''CREATE TABLE enc_priv_keys
                 (public_key_hash TEXT,
                  enc_priv_key TEXT,
                  parameters TEXT,
                  signature TEXT, -- signs enc_priv_key, parameters
                  download_source)''')

    c.execute('''CREATE TABLE certificates
                 (owner TEXT,
                  owner_type TEXT, -- user, node
                  public_key_hash TEXT,
                  signing_key_hash TEXT,
                  trust_level INTEGER,
                  signature TEXT,
                  download_source TEXT)''')

    c.execute('''CREATE TABLE hosts
                 (identity TEXT,
                  public_key_hash TEXT,
                  num_keys INTEGER,
                  connections_text TEXT,
                  connections_sig TEXT,
                  download_source TEXT)''')

    c.execute('''CREATE TABLE connections
                 (host TEXT,
                  publication_stamp INTEGER, -- timestamp of publication 
                  revocation_date INTEGER, -- time to revoke.
                  protocol TEXT,
                  address TEXT,
                  download_source TEXT)''')
    # Should there be information about the reliability of each
    # connection here? I'm not planning on having the hosts
    # send very much between each other....

    # rowid is used here.
    c.execute('''CREATE TABLE storage_quotas
                 (--rowid INTEGER PRIMARY KEY AUTO_INCREMENT,
                  quota_allocated INTEGER,
                  quota_used INTEGER,
                  when_space_exhausted TEXT, -- free_oldest, block
                  parent_quota INTEGER)''')

    # Create the root quota.
    id = add_quota(c, total_quota, 0, 'block', 0)
    assert(id == root_quota_id)

    c.execute('''CREATE TABLE users
                 (user_id TEXT,
                  default_key_hash TEXT,
                  user_quota_id INTEGER,
                  mail_quota_id INTEGER,
                  num_keys INTEGER,
                  default_message_access TEXT, -- overriden by message_access_list. allow, block, proof_of_work/{algorithm=...,...}
                  last_message_time INTEGER,
                  douwnload_source TEXT)''')

    # proof_of_work has a query string or parameters, specifying the algorithm and parameters for the algorithm.
    c.execute('''CREATE TABLE message_access
                 (user_id TEXT,
                  from_key_hash TEXT,
                  access TEXT) -- allow, block, proof_of_work/{algorithm=...,...}''')

    c.execute('''CREATE TABLE messages
                 (message_id TEXT, -- hash(json['SEND_MESSAGE', timestamp, to_user, to_user_key, from_user, from_user_key, message_hash])
                  timestamp INTEGER,
                  to_user TEXT, -- matches users.user_id. Never NULL.
                  to_user_key TEXT, -- OR NULL, matches keys.public_key_hash. key belongs to user.
                  from_user TEXT, -- OR NULL, matches users.user_id
                  from_user_key TEXT, -- OR NULL, matches keys.public_key_hash
                  message TEXT,
                  message_hash TEXT,
                  from_signature TEXT, -- signs message_id
                  proof_of_work TEXT, -- applied to message_id
                  download_source TEXT)''')

    c.execute('''CREATE TABLE groups
                 (group_id TEXT,
                  owner_id TEXT, -- user
                  post_access TEXT,
                  read_access TEXT,
                  delete_access TEXT,
                  posting_key_type TEXT,
                  posting_pub_key TEXT, -- OR NULL
                  reading_key_type TEXT,
                  reading_pub_key TEXT, 
                  delete_key_type TEXT,
                  delete_pub_key TEXT, 
                  quota_id INTEGER,
                  last_post_time INTEGER)''')

    # group access will probably just be managed by sharing keys
    # instead of having whitelists for identities.
    #c.execute('''CREATE TABLE group_access
    #             (group_id TEXT,
    #              owner_id TEXT,
    #              from_key_hash TEXT,
    #              access TEXT) -- allow, block, proof_of_work/{algorithm=...,...}''')

    c.execute('''CREATE TABLE group_posts
                 (post_id TEXT, -- hash(['MAKE_POST', timestamp, group_id, owner_id, data_hash])
                  timestamp INTEGER,
                  group_id TEXT,
                  owner_id TEXT,
                  data TEXT,
                  data_hash TEXT,
                  post_signature TEXT, -- signs post_id
                  proof_of_work TEXT,
                  download_source TEXT)''')

    c.execute('''CREATE TABLE storage_reports
                 (host TEXT,
                  publication_stamp INTEGER,
                  revocation_date INTEGER,
                  report TEXT,
                  signature TEXT,
                  download_source TEXT)''')

    c.execute('''CREATE TABLE complaints
                 (complaint_id TEXT,
                  complainer_id TEXT,
                  complainer_id_type TEXT, -- node or user
                  complainer_key TEXT, -- OR NULL, matches keys.public_key_hash
                  timestamp INTEGER,
                  offensive_node TEXT, -- matches hosts.identity
                  complaint TEXT,
                  signature TEXT, -- OR NULL
                  download_source TEXT)''')


## keys.

def import_key(c, identity, identity_type, key_type, public_key, public_key_hash, revoke_date, trust_score, download_source):
    c.execute('''INSERT INTO keys
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?)''',
                 (identity,
                  identity_type,
                  key_type,
                  public_key,
                  public_key_hash,
                  revoke_date,
                  trust_score,
                  download_source))

def load_key(c, public_key_hash):
    c.execute('SELECT * FROM keys WHERE public_key_hash=?', (public_key_hash,))
    return c.fetchone()

def update_key_trust_score(c, public_key_hash, new_score):
    c.execute('''UPDATE keys SET trust_score=? WHERE public_key_hash=? LIMIT 1''',
              (new_score,
               public_key_hash))


def delete_key(c, public_key_hash):
    c.execute('''DELETE FROM keys WHERE public_key_hash=? LIMIT 1''',
               (public_key_hash,))

def delete_keys_by_owner(c, identity):
    c.execute('''DELETE FROM keys WHERE identity=?''', (identity,))

def delete_revoked_keys(c, date):
    c.execute('''DELETE FROM keys WHERE revoke_date <= ?''', (date,))


def add_private_key(c, public_key_hash, private_key):
    c.execute('''INSERT INTO priv_keys VALUES (?, ?)''',
                (public_key_hash, private_key))

def del_private_key(c, public_key_hash):
    c.execute('''DELETE FROM priv_keys WHERE public_key_hash=?''',
               (public_key_hash,))

 
def add_enc_priv_key(c, public_key_hash, enc_priv_key, parameters, signature, download_source):
    c.execute('''INSERT INTO enc_priv_keys
                 VALUES (?, ?, ?, ?, ?)''',
                 (public_key_hash,
                  enc_priv_key,
                  parameters,
                  signature,
                  download_source))

# key signatures

def add_certificate(c, owner, owner_type, public_key_hash, signing_key_hash, trust_level, signature, download_source):
    c.execute('''INSERT INTO certificates
                 VALUES (?, ?, ?, ?, ?, ?, ?)''',
                 (owner,
                  owner_type,
                  public_key_hash,
                  signing_key_hash,
                  trust_level,
                  signature,
                  download_source))

def remove_certificate(c, public_key_hash, signing_key_hash):
    c.execute('''DELETE FROM certificates WHERE public_key_hash=? and signing_key_hash=? LIMIT 1''',
                 (public_key_hash,
                  signing_key_hash))

def remove_certificates_for_key(c, public_key_hash):
    c.execute('''DELETE FROM certificates WHERE public_key_hash=?''',
                 (public_key_hash,))

def remove_certificates_by_key(c, signing_key_hash):
    c.execute('''DELETE FROM certificates WHERE signing_key_hash=?''',
               (signing_key_hash,))


# hosts

def add_host(c, identity, public_key_hash, num_keys, connections_text, connections_sig, download_source):
    c.execute('''INSERT INTO hosts
                 VALUES (?, ?, ?, ?, ?, ?)''',
                 (identity,
                  public_key_hash,
                  num_keys,
                  connections_text,
                  connections_sig,
                  download_source))

def remove_host(c, identity):
    c.execute('''DELETE FROM hosts WHERE identity=? LIMIT 1''', (identity,))


# connections

def add_connection(c, host, publication_stamp, revocation_date, protocol, address, download_source):
    c.execute('''INSERT INTO connections
                 VALUES (?, ?, ?, ?, ?, ?)''',
                 (host,
                  publication_stamp,
                  revocation_date,
                  protocol,
                  address,
                  download_source))

def remove_connctions_to_host(c, host):
    c.execute('''DELETE FROM connections WHERE host=?''', (host,))

def remove_expired_connections(c, date):
    c.execute('''DELETE FROM connections WHERE revocation_date >= ?''', (date,))
 
# storage quotas

def add_quota(c, quota_allocated, quota_used, when_space_exhausted, parent_quota):
    c.execute('''INSERT INTO storage_quotas
                 VALUES (?, ?, ?, ?)''',
                 (quota_allocated,
                  quota_used,
                  when_space_exhausted,
                  parent_quota))
    c.execute('''SELECT LAST_INSERT_ROWID()''')
    id = c.fetchone()[0]
    return id

def load_quota(c, rowid):
    c.execute('''SELECT * FROM storage_quotas WHERE rowid=? LIMIT 1''', (rowid,))
    return c.fetchone()

def load_quota_obj(c, rowid):
    c.execute('''SELECT quota_allocated, quota_used, when_space_exhausted
                 FROM storage_quotas
                 WHERE rowid=? LIMIT 1''',
                 (rowid,))
    quota_row = c.fetchone()
    assert(quota_row != None)

    (quota_allocated, quota_used, when_space_exhausted) = quota_row

    quota_obj = {'quota_allocated' : quota_allocated,
                 'quota_used' : quota_used,
                 'when_space_exhausted' : when_space_exhausted}

    return quota_obj



def change_quota_used(c, rowid, new_used):
    c.execute('''UPDATE storage_quotas SET quota_used=? WHERE rowid=? LIMIT 1''',
                 (new_used,
                  rowid))

# Trys to increment the quota. 
# On failure raises a QuotaExceededException.
# TODO: optimize to a single sql query.
def try_increment_quota(c, rowid, size):
    row = load_quota(c, rowid)
    assert(row != None)
    (quota_allocated, quota_used, when_space_exhausted, parent_quota) = row
    new_used = quota_used + size
    if new_used > quota_allocated:
        raise ex.QuotaExceededException(rowid, quota_allocated, quota_used, size, when_space_exhausted)
    else:
        change_quota_used(c, rowid, new_used)

def decrease_quota(c, rowid, size):
    c.execute('''UPDATE storage_quotas
                 SET quota_used=MAX(0, quota_used - ?)
                 WHERE rowid=?''',
                 (size,
                  rowid))

def try_create_sub_quota(c, parent_id, size, when_space_exhausted):
    try_increment_quota(c, parent_id, size)
    id = add_quota(c, size, 0, when_space_exhausted, parent_id)
    return id

def try_expand_quota(c, rowid, parent_quota, quota_allocated, new_quota):
    assert(new_quota > quota_allocated)
    increase = new_quota - quota_allocated
    try_increment_quota(c, parent_quota, increase)
    c.execute('UPDATE storage_quotas SET quota_allocated=? WHERE rowid=?',
               (new_quota, rowid))

def try_shrink_quota(c, rowid, parent_quota, quota_allocated, quota_used, new_quota):
    assert(new_quota < quota_allocated)

    if new_quota < quota_used:
        raise ex.QuotaCannotShrinkException(rowid, quota_allocated, quota_used, new_quota)

    decrease = quota_allocated - new_quota

    c.execute('UPDATE storage_quotas SET quota_allocated=? WHERE rowid=?',
              (new_quota, rowid))
    decrease_quota(c, parent_quota, decrease)

def resize_subquota(c, rowid, new_quota):
    row = load_quota(c, rowid)
    assert(row != None)

    (quota_allocated, quota_used, when_space_exhausted, parent_quota) = row

    if new_quota < quota_allocated:
        try_shrink_quota(c, rowid, parent_quota, quota_allocated, quota_used, new_quota)
    elif new_quota > quota_allocated:
        try_expand_quota(c, rowid, parent_quota, quota_allocated, new_quota)

    return row

def change_quota(c, rowid, new_quota, new_when_space_exhausted):
    row = resize_subquota(c, rowid, new_quota)
    (quota_allocated, quota_used, when_space_exhausted, parent_quota) = row

    if when_space_exhausted != new_when_space_exhausted:
        c.execute('UPDATE storage_quotas SET when_space_exhausted=? WHERE rowid=?',
                  (new_when_space_exhausted, rowid))



def remove_quota_raw(c, rowid):
    c.execute('''DELETE FROM storage_quotas WHERE rowid=?''', (rowid,))

# TODO: optimize
def remove_quota(c, rowid):
    c.execute('''SELECT quota_allocated, parent_quota
                 FROM storage_quotas
                 WHERE rowid=? LIMIT 1''',
                 (rowid,))
    (quota_allocated, parent_quota) = c.fetchone()
    if parent_quota != 0:
        decrease_quota(c, parent_quota, quota_allocated)
    remove_quota_raw(c, rowid)


# users

def add_user_raw(c, row):
    (user_id, default_key_hash, user_quota_id, mail_quota_id,
     num_keys, default_message_access, last_message_time, download_source) = row
    c.execute('''INSERT INTO users
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?)''',
                 (user_id,
                  default_key_hash,
                  user_quota_id,
                  mail_quota_id,
                  num_keys,
                  default_message_access,
                  last_message_time,
                  download_source))

def load_user(c, user_id):
    c.execute('''SELECT * FROM users WHERE user_id=? LIMIT 1''', (user_id,))
    return c.fetchone()

def remove_user_raw(c, user_id):
    c.execute('''DELETE FROM users WHERE user_id=? LIMIT 1''', (user_id,))

def remove_user_keys(c, user_id):
    c.execute('''DELETE FROM keys
                 WHERE identity=? AND identity_type="user"''',
                 (user_id,))

def remove_user(c, user_id):
    remove_user_keys(c, user_id) # should keys be removed? what about the web of trust?
    remove_message_accesses(c, user_id)
    remove_messages_to_user(c, user_id)

    for (group_id,) in c.execute('''SELECT group_id FROM groups WHERE owner_id=?''', (user_id,)):
        remove_group(c, group_id, user_id)

    c.execute('''SELECT user_quota_id, mail_quota_id FROM users WHERE user_id=? LIMIT 1''', (user_id,))
    (user_quota_id, mail_quota_id) = c.fetchone()
    remove_quota(c, mail_quota_id)
    remove_quota(c, user_quota_id)
    remove_user_raw(c, user_id)


def create_user(c, node_name, user_id, key_type,
                public_key, public_key_hash, revoke_date,
                default_message_access, when_mail_exhausted,
                parent_quota, quota_size, mail_quota_size):

    finished = False

    trust_score = config.init_trust_score

    ut.assert_access(default_message_access, 'default_message_access')

    ut.assert_non_neg(quota_size, 'quota_size')
    ut.assert_non_neg(mail_quota_size, 'mail_quota_size')

    ut.assert_node_name(node_name, config.node_name)

    if revoke_date != None:
        ut.assert_timestamp(revoke_date, 'revoke_date')

    if mail_quota_size > quota_size:
        raise ex.MailQuotaExceedsUserQuotaException(quota_size, mail_quota_size)

    ut.assert_public_key(key_type, public_key, 'public_key')

    ut.assert_public_key_hash(key_type, public_key, public_key_hash, 'public_key_hash')

    ut.assert_exhaustion(when_mail_exhausted, 'when_mail_exhausted')

    if load_user(c, user_id) != None:
        raise ex.UserNameTakenException(user_id)

    if load_key(c, public_key_hash) != None:
        raise ex.KeyHashExistsException(public_key_hash, 'public_key_hash')

    user_quota = try_create_sub_quota(c, parent_quota, quota_size, "block")

    try:
        mail_quota = try_create_sub_quota(c, user_quota, mail_quota_size, when_mail_exhausted)

        try:
            row = (user_id, public_key_hash, user_quota, mail_quota, 1, default_message_access, None, None)
            size = data_size(row)
            try_increment_quota(c, user_quota, size)
            add_user_raw(c, row)
            import_key(c, user_id, "user", key_type, public_key, public_key_hash, revoke_date, trust_score, None)
            finished = True

        finally:
            if finished != True:
                remove_quota(c, mail_quota)

    finally:
        if finished != True:
            remove_quota(c, user_quota)

def read_user(c, timestamp, node_name, user_id, public_key_hash, signature):
    assert_timestamp_fresh(timestamp, 'timestamp')

    ut.assert_node_name(node_name, config.node_name)

    request_string = ut.serialize_request(['READ_USER', timestamp, node_name, user_id])

    assert_request_signature(c, user_id, 'user', request_string, public_key_hash, signature)

    user_row = load_user(c, user_id)
    if user_row == None:
        # Something's wrong with the database...
        raise ex.UnknownUserException(user_id, 'user_id')

    (user_id, default_key_hash, user_quota_id, mail_quota_id, \
     num_keys, default_message_access, last_message_time, download_source) = user_row

    user_quota_obj = load_quota_obj(c, user_quota_id)
    mail_quota_obj = load_quota_obj(c, mail_quota_id)

    groups_list = []
    for (group_id) in c.execute('''SELECT group_id FROM groups WHERE owner_id=?''', (user_id,)):
        groups_list.append(group_id)

    message_access_list = []
    for (from_key_hash, access) in c.execute('''SELECT from_key_hash, access FROM message_access WHERE user_id=?''', (user_id,)):
        message_access_list.append({'from_key_hash' : from_key_hash, 'access' : access})

    return {'user_id' : user_id,
            'default_key_hash' : default_key_hash,
            'user_quota' : user_quota_obj,
            'mail_quota' : mail_quota_obj,
            'num_keys' : num_keys,
            'default_message_access' : default_message_access,
            'last_message_time' : last_message_time,
            'message_access_list' : message_access_list,
            'groups_list' : groups_list}

def read_last_message_time(c, timestamp, node_name, user_id, public_key_hash, signature):

    assert_timestamp_fresh(timestamp, 'timestamp')

    ut.assert_node_name(node_name, config.node_name)

    request_string = ut.serialize_request(['READ_LAST_MESSAGE_TIME', timestamp, node_name, user_id])

    assert_request_signature(c, user_id, 'user', request_string, public_key_hash, signature)

    c.execute('SELECT last_message_time FROM users WHERE user_id=?', (user_id,))
    user_row = c.fetchone()

    if user_row == None:
        # This case should trip up assert_request_signature
        raise ex.UnknownUserException(user_id, 'user_id')

    (last_post_time,) = user_row

    return last_post_time


def delete_user(c, timestamp, node_name, user_id, public_key_hash, signature):

    assert_timestamp_fresh(timestamp, 'timestamp')

    ut.assert_node_name(node_name, config.node_name)

    request_string = ut.serialize_request(['DELETE_USER', timestamp, node_name, user_id])

    assert_request_signature(c, user_id, 'user', request_string, public_key_hash, signature)

    c.execute('''SELECT user_id FROM users WHERE user_id=? LIMIT 1''', (user_id,))
    row = c.fetchone()

    if row == None:
        raise ex.UnknownUserException(user_id, 'user_id')

    remove_user(c, user_id)


def change_user_quota(c, timestamp, node_name, user_id, new_quota, user_class, auth_token, public_key_hash, signature):

    assert_timestamp_fresh(timestamp, 'timestamp')

    ut.assert_node_name(node_name, config.node_name)

    ut.assert_non_neg(new_quota, 'new_quota')

    request_string = ut.serialize_request(
            ['CHANGE_USER_QUOTA', timestamp, node_name, user_id, new_quota, user_class, auth_token])

    assert_request_signature(c, user_id, 'user', request_string, public_key_hash, signature)

    c.execute('SELECT user_quota_id FROM users WHERE user_id=?', (user_id,))
    user_row = c.fetchone()

    if user_row == None:
        raise ex.UnknownUserException(user_id, 'user_id')

    (user_quota_id,) = user_row

    resize_subquota(c, user_quota_id, new_quota)


def read_user_quota(c, timestamp, node_name, user_id, public_key_hash, signature):

    assert_timestamp_fresh(timestamp, 'timestamp')

    ut.assert_node_name(node_name, config.node_name)

    request_string = ut.serialize_request(
            ['READ_USER_QUOTA', timestamp, node_name, user_id])

    assert_request_signature(c, user_id, 'user', request_string, public_key_hash, signature)

    c.execute('SELECT user_quota_id FROM users WHERE user_id=?', (user_id,))
    user_row = c.fetchone()

    if user_row == None:
        raise UnknownUserException(user_id, 'user_id')

    (user_quota_id,) = user_row

    return load_quota_obj(c, user_quota_id)

def change_message_quota(c, timestamp, node_name, user_id, new_quota, when_mail_exhausted, public_key_hash, signature):

    assert_timestamp_fresh(timestamp, 'timestamp')
    ut.assert_node_name(node_name, config.node_name)
    ut.assert_non_neg(new_quota, 'new_quota')
    ut.assert_exhaustion(when_mail_exhausted, 'when_mail_exhausted')

    request_string = ut.serialize_request(['CHANGE_MESSAGE_QUOTA', timestamp, node_name, user_id, new_quota, when_mail_exhausted])

    assert_request_signature(c, user_id, 'user', request_string, public_key_hash, signature)

    c.execute('SELECT (mail_quota_id) FROM users WHERE user_id=?', (user_id,))
    user_row = c.fetchone()

    if user_row == None:
        raise UnknownUserException(user_id, 'user_id')

    (mail_quota_id,) = user_row

    change_quota(c, mail_quota_id, new_quota, when_mail_exhausted)


def read_message_quota(c, timestamp, node_name, user_id, public_key_hash, signature):

    assert_timestamp_fresh(timestamp, 'timestamp')
    ut.assert_node_name(node_name, config.node_name)

    request_string = ut.serialize_request(['READ_MESSAGE_QUOTA', timestamp, node_name, user_id])

    assert_request_signature(c, user_id, 'user', request_string, public_key_hash, signature)

    c.execute('SELECT mail_quota_id FROM users WHERE user_id=?', (user_id,))
    user_row = c.fetchone()

    if user_row == None:
        raise UnknownUserException(user_id, 'user_id')

    (mail_quota_id,) = user_row

    return load_quota_obj(c, mail_quota_id)




# message_access

def add_message_access_raw(c, row):
    (user_id, from_key_hash, access) = row
    c.execute('''INSERT INTO message_access VALUES (?, ?, ?)''', (user_id, from_key_hash, access))

def load_message_access(c, user_id, from_key_hash):
    c.execute('''SELECT * FROM message_access WHERE user_id=? and from_key_hash=? LIMIT 1''', (user_id, from_key_hash))
    return c.fetchone()

def remove_message_access_raw(c, user_id, from_key_hash):
    c.execute('''DELETE FROM message_access WHERE user_id=? and from_key_hash=? LIMIT 1''', (user_id, from_key_hash))

def remove_message_accesses(c, user_id):
    c.execute('''DELETE FROM message_access WHERE user_id=?''', (user_id,))

def add_message_access(c, row, quota_id):
    (user_id, from_key_hash, access) = row
    ut.assert_access(access, 'access')
    size = data_size(row)
    try_increment_quota(c, quota_id, size)
    add_message_access_raw(c, row)

def remove_message_access(c, user_id, from_key_hash, quota_id):
    row = load_message_access(c, user_id, from_key_hash)
    assert(row)
    size = data_size(row)
    decrease_quota(c, quota_id, size)
    remove_message_access_raw(c, user_id, from_key_hash)


def set_default_message_access(c, user_id, access):

    c.execute('UPDATE users SET default_message_access=? WHERE user_id=?', (access, user_id))

def get_default_message_access(c, user_id):

    c.execute('SELECT default_message_access FROM users WHERE user_id=?', (user_id,))
    row = c.fetchone()
    assert(row != None)
    return row[0]


# if from_key_hash is none, the default message access is set.
def set_message_access(c, timestamp, node_name, user_id, from_key_hash, access, public_key_hash, signature):

    assert_timestamp_fresh(timestamp, 'timestamp')
    ut.assert_node_name(node_name, config.node_name)
    ut.assert_access(access, 'access')

    request_string = ut.serialize_request(
            ['SET_MESSAGE_ACCESS', timestamp, node_name, user_id, from_key_hash, access])

    assert_request_signature(c, user_id, 'user', request_string, public_key_hash, signature)

    if from_key_hash == None:
        set_default_message_access(c, user_id, access)

    else:
        message_access = load_message_access(c, user_id, from_key_hash)
    
        if message_access == None:
            c.execute('SELECT user_quota_id FROM users WHERE user_id=?', (user_id,))
            user_row = c.fetchone()
    
            if user_row == None:
                raise ex.UnknownUserException(user_id, 'user_id')
    
            (user_quota_id,) = user_row
    
            row = (user_id, from_key_hash, access)
            add_message_access(c, row, user_quota_id)
    
        else:
            (user_id, from_key_hash, old_access) = message_access
            if old_access != access:
                c.execute('UPDATE message_access SET access=? WHERE user_id=? AND from_key_hash=?',
                          (access, user_id, from_key_hash))


def read_message_access(c, timestamp, node_name, user_id, from_user_key_hash, public_key_hash, signature):

    assert_timestamp_fresh(timestamp, 'timestamp')
    ut.assert_node_name(node_name, config.node_name)

    request_string = ut.serialize_request(
            ['READ_MESSAGE_ACCESS', timestamp, node_name, user_id, from_user_key_hash])

    assert_request_signature(c, user_id, 'user', request_string, public_key_hash, signature)

    if from_user_key_hash == None:
        access = get_default_message_access(c, user_id)
        return {'user_id' : user_id,
                'from_user_key_hash' : None,
                'access' : access}

    message_access = load_message_access(c, user_id, from_user_key_hash)

    if message_access == None:
        raise ex.UnknownMessageAcessException(user_id, from_user_key_hash)

    else:
        (user_id, from_user_key_hash, access) = message_access

        return {'user_id' : user_id,
                'from_user_key_hash' : from_user_key_hash,
                'access' : access}

def delete_message_access(c, timestamp, node_name, user_id, from_user_key_hash, public_key_hash, signature):

    assert_timestamp_fresh(timestamp, 'timestamp')
    ut.assert_node_name(node_name, config.node_name)

    request_string = ut.serialize_request(
            ['DELETE_MESSAGE_ACCESS', timestamp, node_name, user_id, from_user_key_hash])

    assert_request_signature(c, user_id, 'user', request_string, public_key_hash, signature)

    message_access = load_message_access(c, user_id, from_user_key_hash)

    if message_access == None:
        raise ex.UnknownMessageAcessException(user_id, from_user_key_hash)

    c.execute('SELECT user_quota_id FROM users WHERE user_id=?', (user_id,))
    user_row = c.fetchone()

    if user_row == None:
        raise ex.UnknownUserException(user_id, 'user_id')

    (user_quota_id,) = user_row

    row_size = data_size(message_access)
    decrease_quota(c, user_quota_id, row_size)
    remove_message_access_raw(c, user_id, from_user_key_hash)


# query-message-access

def query_message_access(c, timestamp, node_name, to_user, from_user, from_user_key_hash, signature):

    assert_timestamp_fresh(timestamp, 'timestamp')
    ut.assert_node_name(node_name, 'node_name')

    if from_user_key_hash != None:
        request_string = ut.serialize_request(
                ['QUERY_MESSAGE_ACCESS', timestamp, node_name, to_user, from_user, from_user_key_hash])

        assert_request_signature(c, from_user, 'user', request_string, from_user_key_hash, signature)

    access = get_message_access(c, to_user, from_user_key_hash)

    print ('query_message_access', timestamp, node_name, to_user, from_user, from_user_key_hash, signature, access)

    return {'to_user' : to_user,
            'from_user_key_hash' : from_user_key_hash,
            'access' : access}


# messages

def data_size(row):
    size = 0
    for i in xrange(0, len(row)):
        elt = row[i]
        if elt == None:
            size += 8
        elif (type(elt) == str) or (type(elt) == unicode):
            size += len(elt)
        elif (type(elt) == int) or (type(elt) == long):
            size += 8
        else:
            print ('weird type in data_size', row, i, elt, type(elt))
            assert(False)
    return size

def load_message(c, to_user, message_id):
    c.execute('''SELECT * FROM messages WHERE to_user=? AND message_id=? LIMIT 1''', (to_user, message_id))
    return c.fetchone()

def add_message_raw(c, row):
    (message_id, timestamp, to_user, to_user_key, from_user, from_user_key,
     message, message_hash, from_signature, proof_of_work, download_source) = row
    c.execute('''INSERT INTO messages
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                 (message_id,
                  timestamp,
                  to_user,
                  to_user_key,
                  from_user,
                  from_user_key,
                  message,
                  message_hash,
                  from_signature,
                  proof_of_work,
                  download_source))

def remove_message_raw(c, message_id):
    c.execute('''DELETE FROM messages WHERE message_id=? LIMIT 1''', (message_id,))

def remove_message(c, message_id, quota_id):
    row = load_message(c, message_id)
    size = data_size(row)
    decrease_quota(c, quota_id, size)
    remove_message_raw(c, message_id)

def remove_messages_to_user_key(c, user_key):
    c.execute('''DELETE FROM messages WHERE to_user_key=?''', (user_key,))

def remove_messages_to_user(c, user):
    c.execute('''DELETE FROM messages WHERE to_user=?''', (user,))


# to_user is a valid user_id
def get_message_access(c, to_user, from_key_hash):
    if from_key_hash == None:
        c.execute('''SELECT default_message_access FROM users WHERE user_id=?''', (to_user,))
        return c.fetchone()[0]

    c.execute('''SELECT access FROM message_access WHERE user_id=? AND from_key_hash=?''', (to_user, from_key_hash))
    row = c.fetchone()
    if row == None:
        c.execute('''SELECT default_message_access FROM users WHERE user_id=?''', (to_user,))
        return c.fetchone()[0]

    return row[0]


# message_string is used for signing and proof of work
# it would typically be a json array of all fields except
# signature, proof_of_work, and download_source
def add_message(c, row, node_name):
    (message_id, timestamp, to_user, to_user_key_hash, from_user, from_user_key_hash,
     message, message_hash, from_signature, proof_of_work, download_source) = row

    assert_timestamp_fresh(timestamp, 'timestamp')
    ut.assert_node_name(node_name, config.node_name)

    if to_user == None:
        raise ex.ToUserNameIsNullException()

    ut.assert_hash(message, message_hash, 'message_hash')

    message_id_string = ut.serialize_request(
            ['SEND_MESSAGE', timestamp, node_name,
             to_user, to_user_key_hash,
             from_user, from_user_key_hash,
             message_hash])
    ut.assert_hash(message_id_string, message_id, 'message_id')

    c.execute('''SELECT mail_quota_id, last_message_time FROM users WHERE user_id=? LIMIT 1''', (to_user,))
    user_row = c.fetchone()

    if user_row == None:
        raise ex.UnknownUserException(to_user, 'to_user')

    (mail_quota_id, last_message_time) = user_row

    if to_user_key_hash != None:
        c.execute('''SELECT identity, identity_type FROM keys WHERE public_key_hash=? LIMIT 1''', (to_user_key_hash,))
        to_user_key_row = c.fetchone()

        if to_user_key_row == None:
            raise ex.UnknownKeyException(to_user_key_hash)

        (identity, identity_type) = to_user_key_row
        if identity != to_user or identity_type != 'user':
            raise ex.KeyDoesNotBelongToIdentityException(to_user_key_hash, to_user, 'user', identity, identity_type)

    if from_user_key_hash != None:

        if from_user == None:
            raise ex.FromUserNameIsNullException()

        c.execute('''SELECT identity, identity_type, key_type, public_key FROM keys WHERE public_key_hash=? LIMIT 1''', (from_user_key_hash,))
        from_user_key_row = c.fetchone()

        if from_user_key_row == None:
            raise ex.UnknownKeyException(from_user_key_hash)

        (identity, identity_type, key_type, public_key) = from_user_key_row

        if identity_type != 'user' or from_user != identity:
            raise ex.KeyDoesNotBelongToIdentityException(from_user_key_hash, from_user, 'user', identity, identity_type)

        ut.assert_signature(key_type, public_key, message_id, from_signature, 'message_id')

    access = get_message_access(c, to_user, from_user_key_hash)
    ut.assert_has_access(access, message_id, proof_of_work, 'message_id')

    if last_message_time == None or last_message_time < timestamp:
        c.execute('''UPDATE users SET last_message_time=? WHERE user_id=?''', (timestamp, to_user))
 
    size = data_size(row)
    try_increment_quota(c, mail_quota_id, size)
    add_message_raw(c, row)

def read_message(c, timestamp, node_name, user_id, message_id, public_key_hash, request_signature):

    assert_timestamp_fresh(timestamp, 'timestamp')
    ut.assert_node_name(node_name, config.node_name)

    request_string = ut.serialize_request(
            ['READ_MESSAGE', timestamp, node_name, user_id, message_id])

    assert_request_signature(c, user_id, 'user', request_string, public_key_hash, request_signature)

    row = load_message(c, user_id, message_id)
    if row == None:
        raise ex.UnknownMessageException(user_id, message_id)


    (message_id, timestamp,
     to_user, to_user_key,
     from_user, from_user_key,
     message, message_hash,
     from_signature, proof_of_work, download_source) = row

    return {'message_id' : message_id,
            'timestamp' : timestamp,
            'to_user' : to_user,
            'to_user_key' : to_user_key,
            'from_user' : from_user,
            'from_user_key' : from_user_key,
            'message' : message,
            'message_hash' : message_hash,
            'from_signature' : from_signature,
            'proof_of_work' : proof_of_work}


def delete_message(c, timestamp, node_name, user_id, message_id, public_key_hash, request_signature):

    assert_timestamp_fresh(timestamp, 'timestamp')
    ut.assert_node_name(node_name, config.node_name)

    request_string = ut.serialize_request(['DELETE_MESSAGE', timestamp, node_name, user_id, message_id])

    c.execute('''SELECT mail_quota_id FROM users WHERE user_id=?''', (user_id,))
    user_row = c.fetchone()

    if user_row == None:
        raise ex.UnknownUserException(user_id, 'user_id')

    (mail_quota_id,) = user_row

    assert_request_signature(c, user_id, 'user', request_string, public_key_hash, request_signature)

    row = load_message(c, user_id, message_id)
    if row == None:
        raise ex.UnknownMessageException(user_id, message_id)
    
    size = data_size(row)
    decrease_quota(c, mail_quota_id, size)
    remove_message_raw(c, message_id)


def timestamp_range_sql_string(sql_string, args, start_time, end_time, max_records, order):

    if start_time != None:
        sql_string = sql_string + ' AND timestamp >= ?'
        args.append(start_time)

    if end_time != None:
        sql_string = sql_string + ' AND timestamp <= ?'
        args.append(end_time)

    sql_string += ' ORDER BY timestamp'

    if order == 'desc':
        sql_string = sql_string + ' DESC'

    if max_records != None:
        sql_string = sql_string + ' LIMIT ?'
        args.append(max_records)

    return (sql_string, args)


def read_message_list(c, timestamp, node_name, user_id, start_time, end_time, max_records, order, public_key_hash, request_signature):

    assert_timestamp_fresh(timestamp, 'timestamp')
    ut.assert_node_name(node_name, config.node_name)

    request_string = ut.serialize_request(
            ['READ_MESSAGE_LIST', timestamp, node_name, user_id, start_time, end_time, max_records, order])

    assert_request_signature(c, user_id, 'user', request_string, public_key_hash, request_signature)

    if start_time != None:
        ut.assert_timestamp(start_time, 'start_time')

    if end_time != None:
        ut.assert_timestamp(end_time, 'end_time')

    if max_records != None:
        ut.assert_non_neg(max_records, 'max_records')

    if order != None:
        ut.assert_order(order, 'order')

    sql_string = '''SELECT message_id, timestamp,
                           to_user, to_user_key,
                           from_user, from_user_key,
                           message_hash,
                           from_signature, proof_of_work
                    FROM messages
                    WHERE to_user=?'''

    args = [user_id]

    (sql_string, args) = timestamp_range_sql_string(sql_string, args, start_time, end_time, max_records, order)

    messages = []
    for row in c.execute(sql_string, args):
        (message_id, timestamp,
         to_user, to_user_key,
         from_user, from_user_key,
         message_hash,
         from_signature, proof_of_work) = row

        messages.append({'message_id' : message_id,
                         'timestamp' : timestamp,
                         'to_user' : to_user,
                         'to_user_key' : to_user_key,
                         'from_user' : from_user,
                         'from_user_key' : from_user_key,
                         'message_hash' : message_hash,
                         'from_signature' : from_signature,
                         'proof_of_work' : proof_of_work})

    return messages



# groups

def add_group_raw(c, row):
    (group_id, owner_id, post_access, read_access, delete_access,
     posting_key_type, posting_pub_key,
     reading_key_type, reading_pub_key,
     delete_key_type, delete_pub_key,
     quota_id, last_post_time) = row

    c.execute('''INSERT INTO groups
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                 (group_id,
                  owner_id,
                  post_access,
                  read_access,
                  delete_access,
                  posting_key_type,
                  posting_pub_key,
                  reading_key_type,
                  reading_pub_key,
                  delete_key_type,
                  delete_pub_key,
                  quota_id,
                  last_post_time))

def load_group(c, group_id, owner_id):
    c.execute('''SELECT * FROM groups WHERE group_id=? AND owner_id=?''', (group_id, owner_id))
    return c.fetchone()

def remove_group_raw(c, group_id, owner_id):
    c.execute('''DELETE FROM groups WHERE group_id=? AND owner_id=? LIMIT 1''', (group_id, owner_id))

def remove_group(c, group_id, owner_id):
    c.execute('''SELECT quota_id FROM groups WHERE group_id=? AND owner_id=? LIMIT 1''', (group_id, owner_id))
    quota_id = c.fetchone()[0]
    remove_quota(c, quota_id)
    remove_group_posts(c, group_id, owner_id)
    remove_group_raw(c, group_id, owner_id)


def assert_request_signature(c, request_ident, request_ident_type, request_string, public_key_hash, signature):
    c.execute('''SELECT identity, identity_type, key_type, public_key FROM keys WHERE public_key_hash=? LIMIT 1''',
              (public_key_hash,))
    key_row = c.fetchone()

    if key_row == None:
        raise ex.UnknownKeyException(public_key_hash)

    (identity, identity_type, key_type, public_key) = key_row

    if identity_type != request_ident_type or identity != request_ident:
        raise ex.KeyDoesNotBelongToIdentityException(public_key_hash, request_ident, request_ident_type, identity, identity_type)

    ut.assert_signature(key_type, public_key, request_string, signature, 'request_string')

 
def create_group(c, row, node_name, public_key_hash, request_signature):
    (timestamp, group_id, owner_id,
     post_access, read_access, delete_access,
     posting_key_type, posting_pub_key,
     reading_key_type, reading_pub_key,
     delete_key_type, delete_pub_key,
     quota_allocated, when_space_exhausted) = row

    finished = False

    assert_timestamp_fresh(timestamp, 'timestamp')
    ut.assert_node_name(node_name, config.node_name)

    request_string = ut.serialize_request(
            ['CREATE_GROUP', timestamp, node_name,
             group_id, owner_id,
             post_access, read_access, delete_access,
             posting_key_type, posting_pub_key,
             reading_key_type, reading_pub_key,
             delete_key_type, delete_pub_key,
             quota_allocated, when_space_exhausted])

    assert_request_signature(c, owner_id, 'user', request_string, public_key_hash, request_signature)

    ut.assert_access(post_access, 'post_access')
    ut.assert_access(read_access, 'read_access')
    ut.assert_access(delete_access, 'delete_access')

    if posting_pub_key != None:
        ut.assert_public_key(posting_key_type, posting_pub_key, 'posting_pub_key')
    if reading_pub_key != None:
        ut.assert_public_key(reading_key_type, reading_pub_key, 'reading_pub_key')
    if delete_pub_key != None:
        ut.assert_public_key(delete_key_type, delete_pub_key, 'delete_pub_key')

    ut.assert_non_neg(quota_allocated, 'quota_allocated')

    ut.assert_exhaustion(when_space_exhausted, 'when_space_exhausted')

    existing_row = load_group(c, group_id, owner_id)
    if existing_row != None:
        raise ex.GroupExistsException(group_id, owner_id)

    c.execute('''SELECT user_quota_id FROM users WHERE user_id=? LIMIT 1''', (owner_id,))
    row = c.fetchone()

    if row == None:
        raise ex.UnknownUserException(owner_id, 'owner_id')

    (user_quota_id,) = row
    quota_id = try_create_sub_quota(c, user_quota_id, quota_allocated, when_space_exhausted)

    try:
        row_entry = (group_id, owner_id, post_access, read_access, delete_access,
                     posting_key_type, posting_pub_key,
                     reading_key_type, reading_pub_key,
                     delete_key_type, delete_pub_key,
                     quota_id, None)
        row_size = data_size(row_entry)
        try_increment_quota(c, quota_id, row_size)
        add_group_raw(c, row_entry)
        finished = True

    finally:
        if finished == False:
            remove_quota(c, quota_id)

def read_group(c, timestamp, node_name, group_id, owner_id, public_key_hash, request_signature):

    assert_timestamp_fresh(timestamp, 'timestamp')
    ut.assert_node_name(node_name, config.node_name)

    request_string = ut.serialize_request(
            ['READ_GROUP', timestamp, node_name, group_id, owner_id])

    assert_request_signature(c, owner_id, 'user', request_string, public_key_hash, request_signature)

    row = load_group(c, group_id, owner_id)

    if row == None:
        raise ex.UnknownGroupException(group_id, owner_id)

    (group_id, owner_id, post_access, read_access, delete_access,
     posting_key_type, posting_pub_key,
     reading_key_type, reading_pub_key,
     delete_key_type, delete_pub_key, 
     quota_id, last_post_time) = row

    quota_obj = load_quota_obj(c, quota_id)

    return {'group_id' : group_id,
            'owner_id' : owner_id,
            'post_access' : post_access,
            'read_access' : read_access,
            'delete_access' : delete_access,
            'posting_key_type' : posting_key_type,
            'posting_pub_key' : posting_pub_key,
            'reading_key_type' : reading_key_type,
            'reading_pub_key' : reading_pub_key,
            'delete_key_type' : delete_key_type,
            'delete_pub_key' : delete_pub_key,
            'quota' : quota_obj,
            'last_post_time' : last_post_time}


def read_last_post_time(c, timestamp, node_name, group_id, owner_id, read_signature, proof_of_work):

    assert_timestamp_fresh(timestamp, 'timestamp')
    ut.assert_node_name(node_name, config.node_name)

    request_string = ut.serialize_request(
            ['READ_LAST_POST_TIME', timestamp, node_name, group_id, owner_id])

    c.execute('SELECT read_access, reading_key_type, reading_pub_key, last_post_time FROM groups WHERE group_id=? AND owner_id=?',
              (group_id, owner_id))
    group_row = c.fetchone()

    if group_row == None:
        raise ex.UnknownGroupException(group_id, owner_id)

    (read_access, reading_key_type, reading_pub_key, last_post_time) = group_row

    ut.assert_has_access(read_access, request_string, proof_of_work, 'request_string')

    if reading_pub_key != None:
        ut.assert_signature(reading_key_type, reading_pub_key, request_string, read_signature, 'request_string')

    return last_post_time


def delete_group(c, timestamp, node_name, group_id, owner_id, public_key_hash, request_signature):

    assert_timestamp_fresh(timestamp, 'timestamp')
    ut.assert_node_name(node_name, config.node_name)

    request_string = ut.serialize_request(
            ['DELETE_GROUP', timestamp, node_name, group_id, owner_id])

    assert_request_signature(c, owner_id, 'user', request_string, public_key_hash, request_signature)

    c.execute('''SELECT group_id FROM groups WHERE group_id=? AND owner_id=? LIMIT 1''', (group_id, owner_id))
    row = c.fetchone()

    if row == None:
       raise ex.UnknownGroupException(group_id, owner_id)

    remove_group(c, group_id, owner_id)


def change_group_quota(c,
        timestamp, node_name,
        group_id, owner_id,
        new_quota, when_space_exhausted, public_key_hash, request_signature):

    assert_timestamp_fresh(timestamp, 'timestamp')
    ut.assert_node_name(node_name, config.node_name)

    ut.assert_non_neg(new_quota, 'new_quota')
    ut.assert_exhaustion(when_space_exhausted, 'when_space_exhausted')

    request_string = ut.serialize_request(
            ['CHANGE_GROUP_QUOTA', timestamp, node_name, group_id, owner_id, new_quota, when_space_exhausted])

    assert_request_signature(c, owner_id, 'user', request_string, public_key_hash, request_signature)

    c.execute('SELECT quota_id FROM groups WHERE group_id=? AND owner_id=?',
              (group_id, owner_id))
    group_row = c.fetchone()

    if group_row == None:
        raise ex.UnknownGroupException(group_id, owner_id)

    (quota_id,) = group_row

    change_quota(c, quota_id, new_quota, when_space_exhausted)


def read_group_quota(c, timestamp, node_name, group_id, owner_id, read_signature, proof_of_work):

    assert_timestamp_fresh(timestamp, 'timestamp')
    ut.assert_node_name(node_name, config.node_name)

    request_string = ut.serialize_request(
            ['READ_GROUP_QUOTA', timestamp, node_name, group_id, owner_id])

    c.execute('SELECT read_access, reading_key_type, reading_pub_key, quota_id FROM groups WHERE group_id=? AND owner_id=?',
              (group_id, owner_id))

    group_row = c.fetchone()

    if group_row == None:
        raise ex.UnknownGroupException(group_id, owner_id)

    (read_access, reading_key_type, reading_pub_key, quota_id) = group_row

    ut.assert_has_access(read_access, request_string, proof_of_work, 'request_string')

    if reading_pub_key != None:
        ut.assert_signature(reading_key_type, reading_pub_key, request_string, read_signature, 'request_string')

    return load_quota_obj(c, quota_id)


def change_group_access(c, timestamp, node_name, group_id, owner_id, use, access, public_key_hash, request_signature):

    assert_timestamp_fresh(timestamp, 'timestamp')
    ut.assert_node_name(node_name, config.node_name)

    request_string = ut.serialize_request(
            ['CHANGE_GROUP_ACCESS', timestamp, node_name, group_id, owner_id, use, access])

    assert_request_signature(c, owner_id, 'user', request_string, public_key_hash, request_signature)

#    c.execute('SELECT user_quota_id FROM users WHERE user_id=?', (owner_id,))
#    row = c.fetchone()
#
#    if row == None:
#        # should not happen
#        raise ex.UnknownUserException(owner_id, 'owner_id')
#
#    (user_quota_id,) = row

    c.execute('SELECT * FROM groups WHERE group_id=? AND owner_id=?', (group_id, owner_id))
    row = c.fetchone()

    (group_id, owner_id, post_access, read_access, delete_access,
     posting_key_type, posting_pub_key,
     reading_key_type, reading_pub_key, 
     delete_key_type, delete_pub_key, 
     quota_id, last_post_time) = row

    old_size = data_size(row)
    new_access_size = len(access)

    sql_string = None
    old_access_size = None

    if use == 'post':
        sql_string = 'UPDATE groups SET post_access=? WHERE group_id=? AND owner_id=?'
        old_access_size = len(post_access)

    elif use == 'read':
        sql_string = 'UPDATE groups SET read_access=? WHERE group_id=? AND owner_id=?'
        old_access_size = len(read_access)

    elif use == 'delete':
        sql_string = 'UPDATE groups SET delete_access=? WHERE group_id=? AND owner_id=?'
        old_access_size = len(delete_access)

    else:
        raise ex.BadGroupKeyUseException(use)

    if new_access_size > old_access_size:
        try_increment_quota(c, quota_id, new_access_size - old_access_size)
    elif new_access_size < old_access_size:
        decrease_quota(c, quota_id, old_access_size - new_access_size)

    c.execute(sql_string, (access, group_id, owner_id))


def read_group_access(c, timestamp, node_name, group_id, owner_id, use, request_signature):

    assert_timestamp_fresh(timestamp, 'timestamp')
    ut.assert_node_name(node_name, 'node_name')

    request_string = ut.serialize_request(
            ['READ_GROUP_ACCESS', timestamp, node_name, group_id, owner_id, use])

    sql_string = None

    if use == 'post':
        sql_string = 'SELECT post_access, posting_key_type, posting_pub_key FROM groups WHERE group_id=? AND owner_id=?'

    elif use == 'read':
        sql_string = 'SELECT read_access, reading_key_type, reading_pub_key FROM groups WHERE group_id=? AND owner_id=?'

    elif use == 'delete':
        sql_string = 'SELECT delete_access, delete_key_type, delete_pub_key FROM groups WHERE group_id=? AND owner_id=?'

    else:
        raise ex.BadGroupKeyUseException(use)

    c.execute(sql_string, (group_id, owner_id))
    row = c.fetchone()

    if row == None:
        raise ex.UnknownGroupException(group_id, owner_id)

    (access, key_type, pub_key) = row

    if pub_key != None:
        ut.assert_signature(key_type, pub_key, request_string, request_signature, 'request_string')

    return access


# group_key

def change_group_key(c, timestamp, node_name, group_id, owner_id, key_use, key_type, public_key, public_key_hash, request_signature):

    assert_timestamp_fresh(timestamp, 'timestamp')
    ut.assert_node_name(node_name, 'node_name')

    request_string = ut.serialize_request(
            ['CHANGE_GROUP_KEY', timestamp, node_name, group_id, owner_id, key_use, key_type, public_key])

    assert_request_signature(c, owner_id, 'user', request_string, public_key_hash, request_signature)

    row = load_group(c, group_id, owner_id)

    if row == None:
        raise ex.UnknownGroupException(group_id, owner_id)

    (group_id, owner_id, post_access, read_access, delete_access,
     posting_key_type, posting_pub_key,
     reading_key_type, reading_pub_key,
     delete_key_type, delete_pub_key, 
     quota_id, last_post_time) = row

    sql_string = None
    old_size = None
    new_size = data_size([key_type, public_key])

    if key_use == 'read':
        sql_string = 'UPDATE groups SET reading_key_type=?, reading_pub_key=? WHERE group_id=? AND owner_id=?'
        old_size = data_size([reading_key_type, reading_pub_key])
    elif key_use == 'post':
        sql_string = 'UPDATE groups SET posting_key_type=?, posting_pub_key=? WHERE group_id=? AND owner_id=?'
        old_size = data_size([posting_key_type, posting_pub_key])
    elif key_use == 'delete':
        sql_string = 'UPDATE groups SET delete_key_type=?, delete_pub_key=? WHERE group_id=? AND owner_id=?'
        old_size = data_size([delete_key_type, delete_pub_key])
    else:
        raise ex.BadGroupKeyUseException(key_use)

    if new_size > old_size:
        try_increment_quota(c, quota_id, new_size - old_size)
    elif new_size < old_size:
        decrease_quota(c, quota_id, old_size - new_size)

    c.execute(sql_string, (key_type, public_key, group_id, owner_id))


def read_group_key(c, timestamp, node_name, group_id, owner_id, key_use, public_key_hash, request_signature):

    assert_timestamp_fresh(timestamp, 'timestamp')
    ut.assert_node_name(node_name, 'node_name')

    request_string = ut.serialize_request(
            ['READ_GROUP_KEY', timestamp, node_name, group_id, owner_id, key_use])

    assert_request_signature(c, owner_id, 'user', request_string, public_key_hash, request_signature)

    sql_string = None

    if key_use == 'read':
        sql_string = 'SELECT reading_key_type, reading_pub_key FROM groups WHERE group_id=? AND owner_id=?'
    elif key_use == 'post':
        sql_string = 'SELECT posting_key_type, posting_pub_key FROM groups WHERE group_id=? AND owner_id=?'
    elif key_use == 'delete':
        sql_string = 'SELECT delete_key_type, delete_pub_key FROM groups WHERE group_id=? AND owner_id=?'
    else:
        raise ex.BadGroupKeyUseException(key_use)

    c.execute(sql_string, (group_id, owner_id))
    row = c.fetchone()

    if row == None:
        raise ex.UnknownGroupException(group_id, owner_id)

    (key_type, public_key) = row

    return {'group_id' : group_id,
            'owner_id' : owner_id,
            'key_use' : key_use,
            'key_type' : key_type,
            'public_key' : public_key}



# group_posts

def add_post_raw(c, row):
    (post_id, timestamp, group_id, owner_id, data, data_hash, post_signature, proof_of_work, download_source) = row
    c.execute('''INSERT INTO group_posts
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                 (post_id,
                  timestamp,
                  group_id,
                  owner_id,
                  data,
                  data_hash,
                  post_signature,
                  proof_of_work,
                  download_source))

def remove_post_raw(c, post_id, group_id, owner_id):
    c.execute('''DELETE FROM group_posts WHERE post_id=? AND group_id=? AND owner_id=? LIMIT 1''', (post_id, group_id, owner_id))

def load_post(c, post_id, group_id, owner_id):
    c.execute('''SELECT * FROM group_posts WHERE post_id=? AND group_id=? AND owner_id=? LIMIT 1''', (post_id, group_id, owner_id))
    return c.fetchone()

def remove_post(c, post_id, group_id, owner_id, quota_id):
    row = load_post(c, post_id, group_id, owner_id)
    size = data_size(row)
    decrease_quota(c, quota_id, size)
    remove_post_raw(c, post_id, group_id, owner_id)

def remove_group_posts(c, group_id, owner_id):
    c.execute('''DELETE FROM group_posts WHERE group_id=? AND owner_id=?''', (group_id, owner_id))



def create_post(c, row, node_name):
    (post_id, timestamp, group_id, owner_id, data, data_hash, post_signature, proof_of_work, download_source) = row

    assert_timestamp_fresh(timestamp, 'timestamp')
    ut.assert_node_name(node_name, config.node_name)

    ut.assert_hash(data, data_hash, 'data_hash')

    post_string = ut.serialize_request(
            ['MAKE_POST', timestamp, node_name, group_id, owner_id, data_hash])

    ut.assert_hash(post_string, post_id, 'post_id')

    c.execute('''SELECT quota_id, post_access, posting_key_type, posting_pub_key, last_post_time FROM groups WHERE group_id=? AND owner_id=? LIMIT 1''',
              (group_id, owner_id))
    group_row = c.fetchone()

    if group_row == None:
        raise ex.UnknownGroupException(group_id, owner_id)

    (quota_id, post_access, posting_key_type, posting_pub_key, last_post_time) = group_row

    # Should this be enforced?
    # Differences in latency could prevent users from posting.
    # if timestamp < last_post_time:
    #    raise ex.GroupPostInPastException(timestamp, last_post_time)

    if last_post_time == None or last_post_time < timestamp:
        c.execute('''UPDATE groups SET last_post_time=? WHERE group_id=? AND owner_id=?''', (timestamp, group_id, owner_id))

    c.execute('''SELECT timestamp, data_hash FROM group_posts WHERE post_id=? AND group_id=? AND owner_id=?''', (post_id, group_id, owner_id))
    existing_post = c.fetchone()

    if existing_post != None:
        # try again with a different timestamp
        (existing_timestamp, existing_data_hash) = existing_post
        raise ex.GroupPostIdExists(post_id, existing_timestamp, group_id, owner_id, existing_data_hash)

    ut.assert_has_access(post_access, post_id, proof_of_work, 'post_id')

    if posting_pub_key != None:
        ut.assert_signature(posting_key_type, posting_pub_key, post_id, post_signature, 'post_id')

    size = data_size(row)
    try_increment_quota(c, quota_id, size)
    add_post_raw(c, row)


def delete_post(c, timestamp, node_name, group_id, owner_id, post_id, request_proof_of_work, request_signature):

    assert_timestamp_fresh(timestamp, 'timestamp')
    ut.assert_node_name(node_name, config.node_name)

    request_string = ut.serialize_request(['DELETE_POST', timestamp, node_name, group_id, owner_id, post_id])

    row = load_post(c, post_id, group_id, owner_id)
    if row == None:
        raise ex.UnknownPostException(group_id, owner_id, post_id)

    (post_id, timestamp, group_id, owner_id, data, data_hash, post_signature, proof_of_work, download_source) = row

    c.execute('''SELECT delete_access, delete_key_type, delete_pub_key, quota_id FROM groups WHERE group_id=? AND owner_id=?''', (group_id, owner_id))
    group_row = c.fetchone()

    # If this happens the database is invalid.
    if group_row == None:
        raise ex.UnknownGroupException(group_id, owner_id)

    (delete_access, delete_key_type, delete_pub_key, quota_id) = group_row

    ut.assert_has_access(delete_access, request_string, request_proof_of_work, 'request_string')

    if delete_pub_key != None:
        ut.assert_signature(delete_key_type, delete_pub_key, request_string, request_signature, 'request_string')

    size = data_size(row)
    decrease_quota(c, quota_id, size)
    remove_post_raw(c, post_id, group_id, owner_id)


def read_post(c, timestamp, node_name, group_id, owner_id, post_id, request_proof_of_work, request_signature):

    assert_timestamp_fresh(timestamp, 'timestamp')
    ut.assert_node_name(node_name, config.node_name)

    request_string = ut.serialize_request(['READ_POST', timestamp, node_name, group_id, owner_id, post_id])

    row = load_post(c, post_id, group_id, owner_id)
    if row == None:
        raise ex.UnknownPostException(group_id, owner_id, post_id)

    (post_id, timestamp, group_id, owner_id, data, data_hash, post_signature, proof_of_work, download_source) = row

    c.execute('''SELECT read_access, reading_key_type, reading_pub_key FROM groups WHERE group_id=? AND owner_id=?''', (group_id, owner_id))
    group_row = c.fetchone()

    # The database is invalid.
    if group_row == None:
        raise ex.UnknownGroupException(group_id, owner_id)

    (read_access, reading_key_type, reading_pub_key) = group_row

    ut.assert_has_access(read_access, request_string, request_proof_of_work, 'request_string')

    if reading_pub_key != None:
        ut.assert_signature(reading_key_type, reading_pub_key, request_string, request_signature, 'request_string')

    return {'post_id' : post_id,
            'timestamp' : timestamp,
            'group_id' : group_id,
            'owner_id' : owner_id,
            'data' : data,
            'data_hash' : data_hash,
            'post_signature' : post_signature,
            'proof_of_work' : proof_of_work}
     

def read_post_list(c,
                   timestamp, node_name, group_id, owner_id,
                   start_time, end_time, max_records, order,
                   request_signature, request_proof_of_work):

    assert_timestamp_fresh(timestamp, 'timestamp')
    ut.assert_node_name(node_name, config.node_name)

    if start_time != None:
        ut.assert_timestamp(start_time, 'start_time')

    if end_time != None:
        ut.assert_timestamp(end_time, 'end_time')

    if max_records != None:
        ut.assert_non_neg(max_records, 'max_records')

    if order != None:
        ut.assert_order(order, 'order')

    request_string = ut.serialize_request(
            ['READ_POST_LIST', timestamp, node_name, group_id, owner_id, start_time, end_time, max_records, order])

    c.execute('''SELECT read_access, reading_key_type, reading_pub_key FROM groups WHERE group_id=? AND owner_id=? LIMIT 1''', (group_id, owner_id))
    group_row = c.fetchone()

    if group_row == None:
        raise ex.UnknownGroupException(group_id, owner_id)

    (read_access, reading_key_type, reading_pub_key) = group_row

    ut.assert_has_access(read_access, request_string, request_proof_of_work, 'request_string')

    if reading_pub_key != None:
        ut.assert_signature(reading_key_type, reading_pub_key, request_string, request_signature, 'request_string')


    sql_string = '''SELECT post_id, timestamp,
                           group_id, owner_id,
                           data_hash,
                           post_signature, proof_of_work
                    FROM group_posts
                    WHERE group_id=? AND owner_id=?'''
    args = [group_id, owner_id]

    (sql_string, args) = timestamp_range_sql_string(sql_string, args, start_time, end_time, max_records, order)


    posts = []
    for row in c.execute(sql_string, args):
        (post_id, timestamp,
         group_id, owner_id,
         data_hash,
         post_signature, proof_of_work) = row

        posts.append({'post_id' : post_id,
                      'timestamp' : timestamp,
                      'group_id' : group_id,
                      'owner_id' : owner_id,
                      'data_hash' : data_hash,
                      'post_signature' : post_signature,
                      'proof_of_work' : proof_of_work})

    return posts

# storage_reports

def add_storage_report(c, host, publication_stamp, revocation_date, report, signature, download_source):
    c.execute('''INSERT INTO storage_reports
                 VALUES (?, ?, ?, ?, ?, ?)''',
                 (host,
                  publication_stamp,
                  revocation_date,
                  report,
                  signature,
                  download_source))

def remove_storage_report(c, host, publication_stamp):
    c.execute('''DELETE FROM storage_reports WHERE host=? AND publication_stamp=?''',
                 (host,
                  publication_stamp))

def remove_revoked_storage_reports(c, date):
    c.execute('''DELETE FROM storage_reports WHERE revocation_date <= ?''', (date,))


# complaints

def add_complaint(c, complaint_id, complainer_id, complainer_id_type,
                     complainer_key, timestamp, offensive_node, complaint,
                     signature, download_source):
    c.execute('''INSERT INTO complaints
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?)''',
                 (complaint_id,
                  complainer_id,
                  complainer_id_type,
                  complainer_key,
                  timestamp,
                  offensive_node,
                  complaint,
                  signature,
                  download_source))

def remove_complaint(c, complaint_id):
    c.execute('''DELETE FROM complaints WHERE complaint_id=? LIMIT 1''', (complaint_id,))

def remove_complaints_for_node(c, offensive_node):
    c.execute('''DELETE FROM complaints WHERE offensive_node=?''', (offensive_node,))


# version


def read_version(node_name):

    ut.assert_node_name(node_name, config.node_name)

    return config_proto.version




def read_database(c):

    keys = c.execute('SELECT * FROM keys').fetchall()
    priv_keys = c.execute('SELECT * from priv_keys').fetchall()
    enc_priv_keys = c.execute('SELECT * from enc_priv_keys').fetchall()
    certificates  = c.execute('SELECT * from certificates ').fetchall()
    hosts = c.execute('SELECT * from hosts').fetchall()
    connections = c.execute('SELECT * from connections').fetchall()
    storage_quotas = c.execute('SELECT * from storage_quotas').fetchall()
    users = c.execute('SELECT * from users').fetchall()
    message_access = c.execute('SELECT * from message_access').fetchall()
    messages = c.execute('SELECT * from messages').fetchall()
    groups = c.execute('SELECT * from groups').fetchall()
    group_posts = c.execute('SELECT * from group_posts').fetchall()
    storage_reports = c.execute('SELECT * from storage_reports').fetchall()
    complaints = c.execute('SELECT * from complaints').fetchall()

    return {'keys' : keys,
            'priv_keys' : priv_keys,
            'enc_priv_keys' : enc_priv_keys,
            'certificates' : certificates,
            'hosts' : hosts,
            'connections' : connections,
            'storage_quotas' : storage_quotas,
            'users' : users,
            'message_access' : message_access,
            'messages' : messages,
            'groups' : groups,
            'group_posts' : group_posts,
            'storage_reports' : storage_reports,
            'complaints' : complaints}


def check_integrity(c1, c2, all_local):


    errors = []

    for row in c1.execute('SELECT * FROM keys'):
        (identity, identity_type,
         key_type, public_key, public_key_hash,
         revoke_date, trust_score,
         download_source) = row

        if identity_type == 'user':
            user_row = c2.execute('''SELECT user_id FROM users WHERE user_id=?''', (identity,)).fetchone()
            if user_row == None and all_local:
                errors.append({'table' : 'keys', 'reason' : 'key user gone', 'row' : row})

        elif identity_type == 'node':
            pass
        else:
            assert(False)

    for row in c1.execute('SELECT * FROM enc_priv_keys'):
        (public_key_hash, enc_priv_key,
         parameters, signature,
         download_source) = row

        key_row = c2.execute('''SELECT public_key_hash FROM keys WHERE public_key_hash=?''', (public_key_hash,)).fetchone()
        if key_row == None:
            errors.append({'table' : 'enc_priv_keys', 'reason' : 'key missing', 'row' : row})

    for row in c1.execute('SELECT * FROM certificates'):
        (owner, owner_type,
         public_key_hash, signing_key_hash,
         trust_level, signature,
         download_source) = row

        if owner_type == 'user':
            user_row = c2.execute('SELECT user_id FROM users WHERE user_id=?', (owner,))
            if user_row == None and all_local:
                errors.append({'table' : 'certificates', 'reason' : 'owner missing', 'row' : row})
        elif owner_type == 'node':
            pass
        else:
            assert(False)

        key_row = c2.execute('SELECT public_key_hash FROM keys WHERE public_key_hash=?', (public_key_hash,)).fetchone()
        if key_row == None:
            errors.append({'table' : 'certificates', 'reason' : 'signed key missing', 'row' : row})

        key_row = c2.execute('SELECT public_key_hash FROM keys WHERE public_key_hash=?', (signing_key_hash,)).fetchone()
        if key_row == None:
            errors.append({'table' : 'certificates', 'reason' : 'signing key missing', 'row' : row})

    #'hosts' : hosts,
    #'connections' : connections,

    for row in c1.execute('''SELECT rowid, quota_allocated, quota_used, when_space_exhausted, parent_quota
                             FROM storage_quotas'''):
        
        (rowid, quota_allocated, quota_used, when_space_exhausted, parent_quota) = row

        if parent_quota == 0 and rowid != root_quota_id:
            errors.append({'table' : 'storage_quotas', 'reason' : 'non root has not parent', 'row' : row})
            
        if parent_quota != 0:
            parent_row = c2.execute('SELECT rowid FROM storage_quotas WHERE rowid=?', (parent_quota,)).fetchone()
            if parent_row == None:
                errors.append({'table' : 'storage_quotas', 'reason' : 'parent gone', 'row' : row})

    #'users' : users,

    for row in c1.execute('SELECT * FROM users'):
        (user_id, default_key_hash,
         user_quota_id, mail_quota_id,
         num_keys, default_message_access,
         last_message_time, download_source) = row

        key_row = c2.execute('''SELECT identity, identity_type
                                FROM keys WHERE public_key_hash=?''', (default_key_hash,)).fetchone()
        if key_row == None:
            errors.append({'table' : 'users', 'reason' : 'key missing', 'row' : row})


    for row in c1.execute('SELECT * FROM message_access'):
        (user_id, from_key_hash, access) = row

        user_row = c2.execute('SELECT user_id FROM users WHERE user_id=?', (user_id,)).fetchone()
        if user_row == None:
            errors.append({'table' : 'message_access', 'reason' : 'user gone', 'row' : row})

        key_row = c2.execute('SELECT public_key_hash FROM keys WHERE public_key_hash=?', (from_key_hash,)).fetchone()
        if key_row == None:
            errors.append({'table' : 'message_access', 'reason' : 'from key gone', 'row' : row})


    for row in c1.execute('SELECT * FROM messages'):
        (message_id, timestamp, to_user, to_user_key,
         from_user, from_user_key, message, message_hash,
         from_signature, proof_of_work, download_source) = row

        user_row = c2.execute('SELECT user_id FROM users WHERE user_id=?', (to_user,)).fetchone()
        if user_row == None:
            errors.append({'table' : 'messages', 'reason' : 'to user', 'row' : row})

        if to_user_key != None:
            key_row = c2.execute('SELECT public_key_hash FROM keys WHERE public_key_hash=?', (to_user_key,)).fetchone()
            if key_row == None:
                errors.append({'table' : 'messages', 'reason' : 'to key gone', 'row' : row})

# The from user could have deleted their account.
#
#        if from_user != None:
#            user_row = c2.execute('SELECT user_id FROM users WHERE user_id=?', (from_user,)).fetchone()
#            if user_row == None:
#                errors.append({'table' : 'messages', 'reason' : 'from user gone', 'row' : row})
#
#
# Should the keys be saved for users who have deleted their account?
# If not, this check can't always hold.
#
#        if from_user_key != None:
#            key_row = c2.execute('SELECT public_key_hash FROM keys WHERE public_key_hash=?', (from_user_key,)).fetchone()
#            if key_row == None:
#                errors.append({'table' : 'messages', 'reason' : 'from key gone', 'row' : row})


    for row in c1.execute('SELECT * FROM groups'):
        (group_id, owner_id,
         post_access, read_access, delete_access,
         posting_key_type, posting_pub_key,
         reading_key_type, reading_pub_key,
         delete_key_type, delete_pub_key, 
         quota_id, last_post_time) = row

        user_row = c2.execute('SELECT user_id FROM users WHERE user_id=?', (owner_id,)).fetchone()
        if user_row == None:
            errors.append({'table' : 'groups', 'reason' : 'owner gone', 'row' : row})

        quota_row = c2.execute('SELECT rowid FROM storage_quotas WHERE rowid=?', (quota_id,)).fetchone()
        if quota_row == None:
            errors.append({'table' : 'groups', 'reason' : 'quota gone', 'row' : row})

    for row in c1.execute('SELECT * FROM group_posts'):
        (post_id, timestamp,
         group_id, owner_id,
         data, data_hash,
         post_signature, proof_of_work,
         download_source) = row

        group_row = c2.execute('SELECT group_id FROM groups WHERE group_id=? AND owner_id=?',
                               (group_id, owner_id,)).fetchone()
        if group_row == None:
            errors.append({'table' : 'group_posts', 'reason' : 'group gone', 'row' : row})

        user_row = c2.execute('SELECT user_id FROM users WHERE user_id=?', (owner_id,)).fetchone()
        if user_row == None:
            errors.append({'table' : 'group_posts', 'reason' : 'owner gone', 'row' : row})


    #'storage_reports' : storage_reports,
    #'complaints' : complaints}

    return errors
