import util_client as uc
import Cookie as co



class Client:

    def __init__(self, conn, show_traffic=True):
        self.conn = conn
        self.send_and_getter = uc.SendAndGetter(show_traffic)


    # crypt

    # local/crypt/encrypt.wsgi

    def encrypt(self, user_id, session_id, public_key_hash, plaintext):

        method = 'POST'
        path = '/local/crypt/encrypt'
        body = uc.encode(
                {'public_key_hash' : public_key_hash,
                 'plaintext' : plaintext})
        cookies = co.SimpleCookie({'user_id' : user_id, 'session_id' : session_id})

        return self.send_and_getter.send_and_get(self.conn, method, path, body, cookies)[0]


    # local/crypt/decrypt.wsgi

    def decrypt(self, user_id, session_id, public_key_hash, ciphertext, passphrase=None):

        method = 'POST'
        path = '/local/crypt/decrypt'
        body = uc.encode(
                {'public_key_hash' : public_key_hash,
                 'ciphertext' : ciphertext,
                 'passphrase' : passphrase})
        cookies = co.SimpleCookie({'user_id' : user_id, 'session_id' : session_id})

        return self.send_and_getter.send_and_get(self.conn, method, path, body, cookies)[0]


    # local/crypt/verify_signature.wsgi

    def verify_signature(self, user_id, session_id, public_key_hash, data, signature):

        method = 'POST'
        path = '/local/crypt/verify-signature'
        body = uc.encode(
                {'public_key_hash' : public_key_hash,
                 'data' : data,
                 'signature' : signature})
        cookies = co.SimpleCookie({'user_id' : user_id, 'session_id' : session_id})

        return self.send_and_getter.send_and_get(self.conn, method, path, body, cookies)[0]


    # local/crypt/sign.wsgi

    def sign(self, user_id, session_id, public_key_hash, data, passphrase):

        method = 'POST'
        path = '/local/crypt/sign'
        body = uc.encode(
                {'public_key_hash' : public_key_hash,
                 'data' : data,
                 'passphrase' : passphrase})
        cookies = co.SimpleCookie({'user_id' : user_id, 'session_id' : session_id})

        return self.send_and_getter.send_and_get(self.conn, method, path, body, cookies)[0]


    # config
    
    # local/public-key.wsgi
    
    def read_public_key(self, user_id, session_id, public_key_hash):
    
        method = 'GET'
        path = '/local/public-key?' + uc.encode(
                {'public_key_hash' : public_key_hash})
        cookies = co.SimpleCookie({'user_id' : user_id, 'session_id' : session_id})
    
        return self.send_and_getter.send_and_get(self.conn, method, path, body=None, cookies=cookies)[0]
    
    
    def delete_public_key(self, user_id, session_id, public_key_hash):
    
        method = 'DELETE'
        path = '/local/public-key'
        body = uc.encode(
                {'public_key_hash' : public_key_hash})
        cookies = co.SimpleCookie({'user_id' : user_id, 'session_id' : session_id})
    
        return self.send_and_getter.send_and_get(self.conn, method, path, body=body, cookies=cookies)[0]
    
    
    def import_public_key(self, user_id, session_id, key_type, public_key, revoke_date):
    
        method = 'POST'
        path = '/local/public-key'
        body = uc.encode(
                {'key_type' : key_type,
                 'public_key' : public_key,
                 'revoke_date' : revoke_date})
        cookies = co.SimpleCookie({'user_id' : user_id, 'session_id' : session_id})
    
        return self.send_and_getter.send_and_get(self.conn, method, path, body=body, cookies=cookies)[0]
    
    
    # local/private-key.wsgi
    
    def read_private_key(self, user_id, session_id, public_key_hash):
    
        method = 'GET'
        path = '/local/private-key?' + uc.encode(
                {'public_key_hash' : public_key_hash})
        cookies = co.SimpleCookie({'user_id' : user_id, 'session_id' : session_id})
    
        return self.send_and_getter.send_and_get(self.conn, method, path, body=None, cookies=cookies)[0]
    
    def delete_private_key(self, user_id, session_id, public_key_hash):
    
        method = 'DELETE'
        path = '/local/private-key'
        body = uc.encode(
                {'public_key_hash' : public_key_hash})
        cookies = co.SimpleCookie({'user_id' : user_id, 'session_id' : session_id})
    
        return self.send_and_getter.send_and_get(self.conn, method, path, body=body, cookies=cookies)[0]
    
    def import_private_key(self, user_id, session_id, key_type, public_key, private_key, revoke_date):
    
        method = 'POST'
        path = '/local/private-key'
        body = uc.encode(
                {'key_type' : key_type,
                 'public_key' : public_key,
                 'private_key' : private_key,
                 'revoke_date' : revoke_date})
        cookies = co.SimpleCookie({'user_id' : user_id, 'session_id' : session_id})
    
        return self.send_and_getter.send_and_get(self.conn, method, path, body=body, cookies=cookies)[0]
    
    # local/crypt/gen-key.wsgi
    
    def generate_private_key(self, user_id, session_id, key_type, key_parameters, revoke_date, passphrase=None):
    
        method = 'POST'
        path = '/local/crypt/gen-key'
        body = uc.encode(
                {'key_type' : key_type,
                 'key_parameters' : key_parameters,
                 'revoke_date' : revoke_date,
                 'passphrase' : passphrase})
        cookies = co.SimpleCookie({'user_id' : user_id, 'session_id' : session_id})
    
        return self.send_and_getter.send_and_get(self.conn, method, path, body=body, cookies=cookies)[0]
    
    
    # local/group-key.wsgi
    
    def read_local_group_key(self, user_id, session_id, group_id, owner_id, key_use):
    
        method = 'GET'
        path = '/local/group-key?' + uc.encode(
                {'owner_id' : owner_id,
                 'group_id' : group_id,
                 'key_use' : key_use})
        cookies = co.SimpleCookie({'user_id' : user_id, 'session_id' : session_id})
    
        return self.send_and_getter.send_and_get(self.conn, method, path, body=None, cookies=cookies)[0]
    
    def delete_local_group_key(self, user_id, session_id, group_id, owner_id, key_use):
    
        method = 'DELETE'
        path = '/local/group-key'
        body = uc.encode(
                {'owner_id' : owner_id,
                 'group_id' : group_id,
                 'key_use' : key_use})
        cookies = co.SimpleCookie({'user_id' : user_id, 'session_id' : session_id})
    
        return self.send_and_getter.send_and_get(self.conn, method, path, body=body, cookies=cookies)[0]
    
    def assign_local_group_key(self, user_id, session_id, group_id, owner_id, key_use, public_key_hash):
    
        method = 'POST'
        path = '/local/group-key'
        body = uc.encode(
                {'owner_id' : owner_id,
                 'group_id' : group_id,
                 'key_use' : key_use,
                 'public_key_hash' : public_key_hash})
        cookies = co.SimpleCookie({'user_id' : user_id, 'session_id' : session_id})
    
        return self.send_and_getter.send_and_get(self.conn, method, path, body=body, cookies=cookies)[0]


    # local/list-public-keys.wsgi

    def list_public_keys(self, user_id, session_id):

        method = 'GET'
        path = '/local/list-public-keys'
        cookies = co.SimpleCookie({'user_id' : user_id, 'session_id' : session_id})

        return self.send_and_getter.send_and_get(self.conn, method, path, body=None, cookies=cookies)[0]


    # local/list-private-keys.wsgi

    def list_private_keys(self, user_id, session_id):

        method = 'GET'
        path = '/local/list-private-keys'
        cookies = co.SimpleCookie({'user_id' : user_id, 'session_id' : session_id})

        return self.send_and_getter.send_and_get(self.conn, method, path, body=None, cookies=cookies)[0]


    # local/list-user-keys.wsgi

    def list_user_keys(self, user_id, session_id):

        method = 'GET'
        path = '/local/list-user-keys'
        cookies = co.SimpleCookie({'user_id' : user_id, 'session_id' : session_id})

        return self.send_and_getter.send_and_get(self.conn, method, path, body=None, cookies=cookies)[0]


    # local/list-group-keys.wsgi

    def list_group_keys(self, user_id, session_id):

        method = 'GET'
        path = '/local/list-group-keys'
        cookies = co.SimpleCookie({'user_id' : user_id, 'session_id' : session_id})

        return self.send_and_getter.send_and_get(self.conn, method, path, body=None, cookies=cookies)[0]


    # local/list-other-user-keys.wsgi

    def list_other_user_keys(self, user_id, session_id):

        method = 'GET'
        path = '/local/list-other-user-keys'
        cookies = co.SimpleCookie({'user_id' : user_id, 'session_id' : session_id})

        return self.send_and_getter.send_and_get(self.conn, method, path, body=None, cookies=cookies)[0]


    # local/user-key.wsgi
    
    def read_user_key(self, user_id, session_id, public_key_hash):
    
        method = 'GET'
        path = '/local/user-key?' + uc.encode(
                {'public_key_hash' : public_key_hash})
        cookies = co.SimpleCookie({'user_id' : user_id, 'session_id' : session_id})
    
        return self.send_and_getter.send_and_get(self.conn, method, path, body=None, cookies=cookies)[0]
    
    def delete_user_key(self, user_id, session_id, public_key_hash):
    
        method = 'DELETE'
        path = '/local/user-key'
        body = uc.encode(
                {'public_key_hash' : public_key_hash})
        cookies = co.SimpleCookie({'user_id' : user_id, 'session_id' : session_id})
    
        return self.send_and_getter.send_and_get(self.conn, method, path, body=body, cookies=cookies)[0]
    
    def assign_user_key(self, user_id, session_id, public_key_hash):
    
        method = 'POST'
        path = '/local/user-key'
        body = uc.encode(
                {'public_key_hash' : public_key_hash})
        cookies = co.SimpleCookie({'user_id' : user_id, 'session_id' : session_id})
    
        return self.send_and_getter.send_and_get(self.conn, method, path, body=body, cookies=cookies)[0]
    
    
    # local/other-user-key.wsgi
    
    def read_other_user_key(self, user_id, session_id, other_user_id, public_key_hash):
    
        method = 'GET'
        path = '/local/other-user-key?' + uc.encode(
                {'other_user_id' : other_user_id,
                 'public_key_hash' : public_key_hash})
        cookies = co.SimpleCookie({'user_id' : user_id, 'session_id' : session_id})
    
        return self.send_and_getter.send_and_get(self.conn, method, path, body=None, cookies=cookies)[0]
    
    def delete_other_user_key(self, user_id, session_id, other_user_id, public_key_hash):
    
        method = 'DELETE'
        path = '/local/other-user-key'
        body = uc.encode(
                {'other_user_id' : other_user_id,
                 'public_key_hash' : public_key_hash})
        cookies = co.SimpleCookie({'user_id' : user_id, 'session_id' : session_id})
    
        return self.send_and_getter.send_and_get(self.conn, method, path, body=body, cookies=cookies)[0]
    
    def assign_other_user_key(self, user_id, session_id, other_user_id, public_key_hash, trust_score):
    
        method = 'POST'
        path = '/local/other-user-key'
        body = uc.encode(
                {'other_user_id' : other_user_id,
                 'public_key_hash' : public_key_hash,
                 'trust_score' : trust_score})
        cookies = co.SimpleCookie({'user_id' : user_id, 'session_id' : session_id})
    
        return self.send_and_getter.send_and_get(self.conn, method, path, body=body, cookies=cookies)[0]
    
    
    # local/node-addr.wsgi
    
    def read_node_addr(self, user_id, session_id, node_name):
    
        method = 'GET'
        path = '/local/node-addr?' + uc.encode(
                {'node_name' : node_name})
        cookies = co.SimpleCookie({'user_id' : user_id, 'session_id' : session_id})
    
        return self.send_and_getter.send_and_get(self.conn, method, path, body=None, cookies=cookies)[0]
    
    def delete_node_addr(self, user_id, session_id, node_name):
    
        method = 'DELETE'
        path = '/local/node-addr'
        body = uc.encode(
                {'node_name' : node_name})
        cookies = co.SimpleCookie({'user_id' : user_id, 'session_id' : session_id})
    
        return self.send_and_getter.send_and_get(self.conn, method, path, body=body, cookies=cookies)[0]
    
    def set_node_addr(self, user_id, session_id, node_name, url):
    
        method = 'POST'
        path = '/local/node-addr'
        body = uc.encode(
                {'node_name' : node_name,
                 'url' : url})
        cookies = co.SimpleCookie({'user_id' : user_id, 'session_id' : session_id})
    
        return self.send_and_getter.send_and_get(self.conn, method, path, body=body, cookies=cookies)[0]
    
    # local/group-access.wsgi
    
    def read_local_group_access(self, user_id, session_id, group_id, owner_id, use):
    
        method = 'GET'
        path = '/local/group-access?' + uc.encode(
                {'owner_id' : owner_id,
                 'group_id' : group_id,
                 'use' : use})
        cookies = co.SimpleCookie({'user_id' : user_id, 'session_id' : session_id})
    
        return self.send_and_getter.send_and_get(self.conn, method, path, body=None, cookies=cookies)[0]
    
    def delete_local_group_access(self, user_id, session_id, group_id, owner_id, use):
    
        method = 'DELETE'
        path = '/local/group-access'
        body = uc.encode(
                {'owner_id' : owner_id,
                 'group_id' : group_id,
                 'use' : use})
        cookies = co.SimpleCookie({'user_id' : user_id, 'session_id' : session_id})
    
        return self.send_and_getter.send_and_get(self.conn, method, path, body=body, cookies=cookies)[0]
    
    def set_local_group_access(self, user_id, session_id, group_id, owner_id, use, access, timestamp=None):
    
        method = 'POST'
        path = '/local/group-access'
        body = uc.encode(
                {'owner_id' : owner_id,
                 'group_id' : group_id,
                 'use' : use,
                 'access' : access,
                 'timestamp' : timestamp})
        cookies = co.SimpleCookie({'user_id' : user_id, 'session_id' : session_id})
    
        return self.send_and_getter.send_and_get(self.conn, method, path, body=body, cookies=cookies)[0]
    
    
    # local/message-access.wsgi
    
    def read_local_message_access(self, user_id, session_id, to_user, from_user_key_hash):
    
        method = 'GET'
        path = '/local/message-access?' + uc.encode(
                {'to_user' : to_user,
                 'from_user_key_hash' : from_user_key_hash})
        cookies = co.SimpleCookie({'user_id' : user_id, 'session_id' : session_id})
    
        return self.send_and_getter.send_and_get(self.conn, method, path, body=None, cookies=cookies)[0]
    
    def delete_local_message_access(self, user_id, session_id, to_user, from_user_key_hash):
    
        method = 'DELETE'
        path = '/local/message-access'
        body = uc.encode(
                {'to_user' : to_user,
                 'from_user_key_hash' : from_user_key_hash})
        cookies = co.SimpleCookie({'user_id' : user_id, 'session_id' : session_id})
    
        return self.send_and_getter.send_and_get(self.conn, method, path, body=body, cookies=cookies)[0]
    
    def set_local_message_access(self, user_id, session_id, to_user, from_user_key_hash, access, timestamp=None):
    
        method = 'POST'
        path = '/local/message-access'
        body = uc.encode(
                {'to_user' : to_user,
                 'from_user_key_hash' : from_user_key_hash,
                 'access' : access,
                 'timestamp' : timestamp})
        cookies = co.SimpleCookie({'user_id' : user_id, 'session_id' : session_id})
    
        return self.send_and_getter.send_and_get(self.conn, method, path, body=body, cookies=cookies)[0]
    
    # local/password.wsgi
    
    
    def read_password(self, user_id, session_id):
    
        method = 'GET'
        path = '/local/password' 
        cookies = co.SimpleCookie({'user_id' : user_id, 'session_id' : session_id})
    
        return self.send_and_getter.send_and_get(self.conn, method, path, body=None, cookies=cookies)[0]
    
    
    def set_password(self, user_id, session_id, method, password=None, public_key_hash=None):
    
        method = 'POST'
        path = '/local/password'
        body = uc.encode(
                {'method' : method,
                 'password' : password,
                 'public_key_hash' : public_key_hash})
        cookies = co.SimpleCookie({'user_id' : user_id, 'session_id' : session_id})
    
        return self.send_and_getter.send_and_get(self.conn, method, path, body=body, cookies=cookies)[0]
    
    
    # local/login.wsgi
    
    def login(self, user_id, password):
    
        method = 'POST'
        path = '/local/login'
        body = uc.encode(
                {'user_id' : user_id,
                 'password' : password})
    
        return self.send_and_getter.send_and_get(self.conn, method, path, body=body, cookies=None)
    
    
    # local/sign-out.wsgi
    
    def sign_out(self, user_id, session_id):
    
        method = 'GET'
        path = '/local/sign-out'
        cookies = co.SimpleCookie({'user_id' : user_id, 'session_id' : session_id})
    
        return self.send_and_getter.send_and_get(self.conn, method, path, body=None, cookies=cookies)
    
    
    # local/user.wsgi
    
    
    def create_local_user(self, user_id, password):
    
        method = 'POST'
        path = '/local/user'
        body = uc.encode(
                {'user_id' : user_id,
                 'password' : password})
    
        return self.send_and_getter.send_and_get(self.conn, method, path, body=body, cookies=None)
    
    
    def delete_local_user(self, user_id, session_id):
    
        method = 'DELETE'
        path = '/local/user'
        cookies = co.SimpleCookie({'user_id' : user_id, 'session_id' : session_id})
    
        return self.send_and_getter.send_and_get(self.conn, method, path, body=None, cookies=cookies)
    
    
    
    # local/version.wsgi
    
    def read_local_version(self):
    
        method = 'GET'
        path = '/local/version'
    
        return self.send_and_getter.send_and_get(self.conn, method, path, body=None, cookies=None)[0]
    
    
    # local/debug.wsgi
    
    def local_debug(self, action):
    
        method = 'GET'
        path = '/local/debug?' + uc.encode({'action' : action})
    
        return self.send_and_getter.send_and_get(self.conn, method, path, body=None, cookies=None)[0]
    
    
    def assert_db_empty(self):
    
        resp = self.local_debug('database')
        assert(resp['status'] == 'ok')
        database = resp['database']
    
        assert(len(database['user_passwords']) == 0)
        assert(len(database['group_keys']) == 0)
        assert(len(database['other_user_keys']) == 0)
        assert(len(database['user_keys']) == 0)
        assert(len(database['private_keys']) == 0)
        assert(len(database['public_keys']) == 0)
        assert(len(database['sessions']) == 0)
        assert(len(database['node_addr']) == 0)
        assert(len(database['message_access']) == 0)
        assert(len(database['group_access']) == 0)
    
    
    
    
    # Node
    
    #proxy/complain.wsgi
    
    #proxy/group-access.wsgi
    
    def read_group_access(self, user_id, session_id, node_name, group_id, owner_id, use, passphrase=None):
    
        method = 'GET'
        path = '/proxy/group-access?' + uc.encode(
                {'node_name' : node_name,
                 'group_id' : group_id,
                 'owner_id' : owner_id,
                 'use' : use,
                 'passphrase' : passphrase})
        cookies = co.SimpleCookie({'user_id' : user_id, 'session_id' : session_id})
    
        return self.send_and_getter.send_and_get(self.conn, method, path, body=None, cookies=cookies)[0]
    
    
    def set_group_access(self, user_id, session_id, node_name, group_id, use, access, public_key_hash, passphrase=None):
    
        method = 'POST'
        path = '/proxy/group-access'
        body = uc.encode(
                {'node_name' : node_name,
                 'group_id' : group_id,
                 'use' : use,
                 'access' : access,
                 'public_key_hash' : public_key_hash,
                 'passphrase' : passphrase})
        cookies = co.SimpleCookie({'user_id' : user_id, 'session_id' : session_id})
    
        return self.send_and_getter.send_and_get(self.conn, method, path, body=body, cookies=cookies)[0]
    
    #proxy/group-key.wsgi

    def read_group_key(self, user_id, session_id, node_name, group_id, key_use, public_key_hash, passphrase=None):
    
        method = 'GET'
        path = '/proxy/group-key?' + uc.encode(
                {'node_name' : node_name,
                 'group_id' : group_id,
                 'key_use' : key_use,
                 'public_key_hash' : public_key_hash,
                 'passphrase' : passphrase})
        cookies = co.SimpleCookie({'user_id' : user_id, 'session_id' : session_id})
    
        return self.send_and_getter.send_and_get(self.conn, method, path, body=None, cookies=cookies)[0]
    
    
    def set_group_key(self, user_id, session_id, node_name, group_id, key_use, group_key_hash, public_key_hash, passphrase=None):
    
        method = 'POST'
        path = '/proxy/group-key'
        body = uc.encode(
                {'node_name' : node_name,
                 'group_id' : group_id,
                 'key_use' : key_use,
                 'group_key_hash' : group_key_hash,
                 'public_key_hash' : public_key_hash,
                 'passphrase' : passphrase})
        cookies = co.SimpleCookie({'user_id' : user_id, 'session_id' : session_id})
    
        return self.send_and_getter.send_and_get(self.conn, method, path, body=body, cookies=cookies)[0]

    
    # proxy/group-config.wsgi
    
    # proxy/group-quota.wsgi
    
    
    def read_group_quota(self, user_id, session_id, node_name, group_id, owner_id, passphrase=None):
    
        method = 'GET'
        path = '/proxy/group-quota?' + uc.encode(
                {'node_name' : node_name,
                 'group_id' : group_id,
                 'owner_id' : owner_id,
                 'passphrase' : passphrase})
        cookies = co.SimpleCookie({'user_id' : user_id, 'session_id' : session_id})
    
        return self.send_and_getter.send_and_get(self.conn, method, path, body=None, cookies=cookies)[0]
    
    
    def change_group_quota(self, user_id, session_id, node_name, group_id, new_size, when_space_exhausted, public_key_hash, passphrase=None):
    
        method = 'POST'
        path = '/proxy/group-quota'
        body = uc.encode(
                {'node_name' : node_name,
                 'group_id' : group_id,
                 'new_size' : new_size,
                 'when_space_exhausted' : when_space_exhausted,
                 'public_key_hash' : public_key_hash,
                 'passphrase' : passphrase})
        cookies = co.SimpleCookie({'user_id' : user_id, 'session_id' : session_id})
    
        return self.send_and_getter.send_and_get(self.conn, method, path, body=body, cookies=cookies)[0]
    
    
    # proxy/group.wsgi
    
    
    def read_group(self, user_id, session_id, node_name, group_id, public_key_hash, passphrase=None):
    
        method = 'GET'
        path = '/proxy/group?' + uc.encode(
                {'node_name' : node_name,
                 'group_id' : group_id,
                 'public_key_hash' : public_key_hash,
                 'passphrase' : passphrase})
        cookies = co.SimpleCookie({'user_id' : user_id, 'session_id' : session_id})
    
        return self.send_and_getter.send_and_get(self.conn, method, path, body=None, cookies=cookies)[0]
    
    def delete_group(self, user_id, session_id, node_name, group_id, public_key_hash, passphrase=None):
    
        method = 'DELETE'
        path = '/proxy/group'
        body = uc.encode(
                {'node_name' : node_name,
                 'group_id' : group_id,
                 'public_key_hash' : public_key_hash,
                 'passphrase' : passphrase})
        cookies = co.SimpleCookie({'user_id' : user_id, 'session_id' : session_id})
    
        return self.send_and_getter.send_and_get(self.conn, method, path, body=body, cookies=cookies)[0]
    
    def create_group(self, user_id, session_id, node_name, group_id, quota_allocated, when_space_exhausted, public_key_hash, passphrase=None):
    
        method = 'POST'
        path = '/proxy/group'
        body = uc.encode(
                {'node_name' : node_name,
                 'group_id' : group_id,
                 'quota_allocated' : quota_allocated,
                 'when_space_exhausted' : when_space_exhausted,
                 'public_key_hash' : public_key_hash,
                 'passphrase' : passphrase})
        cookies = co.SimpleCookie({'user_id' : user_id, 'session_id' : session_id})
    
        return self.send_and_getter.send_and_get(self.conn, method, path, body=body, cookies=cookies)[0]
    
    
    
    # proxy/last-message-time.wsgi
    
    def read_last_message_time(self, user_id, session_id, node_name, public_key_hash, passphrase=None):
    
        method = 'GET'
        path = '/proxy/last-message-time?' + uc.encode(
                {'node_name' : node_name,
                 'public_key_hash' : public_key_hash,
                 'passphrase' : passphrase})
        cookies = co.SimpleCookie({'user_id' : user_id, 'session_id' : session_id})
    
        return self.send_and_getter.send_and_get(self.conn, method, path, body=None, cookies=cookies)[0]
    
    
    # proxy/last-post-time.wsgi
    
    def read_last_post_time(self, user_id, session_id, node_name, group_id, owner_id, passphrase=None):
    
        method = 'GET'
        path = '/proxy/last-post-time?' + uc.encode(
                {'node_name' : node_name,
                 'group_id' : group_id,
                 'owner_id' : owner_id,
                 'passphrase' : passphrase})
        cookies = co.SimpleCookie({'user_id' : user_id, 'session_id' : session_id})
    
        return self.send_and_getter.send_and_get(self.conn, method, path, body=None, cookies=cookies)[0]
    
    
    # proxy/query-message-access.wsgi
    
    def query_message_access(self, user_id, session_id, node_name, to_user, from_user_key_hash, passphrase):
    
        method = 'GET'
        path = '/proxy/query-message-access?' + uc.encode(
                {'node_name' : node_name,
                 'to_user' : to_user,
                 'from_user_key_hash' : from_user_key_hash,
                 'passphrase' : passphrase})
        cookies = co.SimpleCookie({'user_id' : user_id, 'session_id' : session_id})
    
        return self.send_and_getter.send_and_get(self.conn, method, path, body=None, cookies=cookies)[0]
    
    
    # proxy/message-access.wsgi
    
    def read_message_access(self, user_id, session_id, node_name, from_user_key_hash, public_key_hash, passphrase=None):
    
        method = 'GET'
        path = '/proxy/message-access?' + uc.encode(
                {'node_name' : node_name,
                 'from_user_key_hash' : from_user_key_hash,
                 'public_key_hash' : public_key_hash,
                 'passphrase' : passphrase})
        cookies = co.SimpleCookie({'user_id' : user_id, 'session_id' : session_id})
    
        return self.send_and_getter.send_and_get(self.conn, method, path, body=None, cookies=cookies)[0]
    
    def delete_message_access(self, user_id, session_id, node_name, from_user_key_hash, public_key_hash, passphrase=None):
    
        method = 'DELETE'
        path = '/proxy/message-access'
        body = uc.encode(
                {'node_name' : node_name,
                 'from_user_key_hash' : from_user_key_hash,
                 'public_key_hash' : public_key_hash,
                 'passphrase' : passphrase})
        cookies = co.SimpleCookie({'user_id' : user_id, 'session_id' : session_id})
    
        return self.send_and_getter.send_and_get(self.conn, method, path, body=body, cookies=cookies)[0]
    
    def set_message_access(self, user_id, session_id, node_name, from_user_key_hash, access, public_key_hash, passphrase=None):
    
        method = 'POST'
        path = '/proxy/message-access'
        body = uc.encode(
                {'node_name' : node_name,
                 'from_user_key_hash' : from_user_key_hash,
                 'access' : access,
                 'public_key_hash' : public_key_hash,
                 'passphrase' : passphrase})
        cookies = co.SimpleCookie({'user_id' : user_id, 'session_id' : session_id})
    
        return self.send_and_getter.send_and_get(self.conn, method, path, body=body, cookies=cookies)[0]
    
    
    # proxy/message-list.wsgi
    
    def read_message_list(self, user_id, session_id, node_name, start_time, end_time, max_records, order, public_key_hash, passphrase=None):
    
        method = 'GET'
        path = '/proxy/message-list?' + uc.encode(
                {'node_name' : node_name,
                 'start_time' : start_time,
                 'end_time' : end_time,
                 'max_records' : max_records,
                 'order' : order,
                 'public_key_hash' : public_key_hash,
                 'passphrase' : passphrase})
        cookies = co.SimpleCookie({'user_id' : user_id, 'session_id' : session_id})
    
        return self.send_and_getter.send_and_get(self.conn, method, path, body=None, cookies=cookies)[0]
    
    
    # proxy/message-quota.wsgi
    
    def read_message_quota(self, user_id, session_id, node_name, public_key_hash, passphrase=None):
    
        method = 'GET'
        path = '/proxy/message-quota?' + uc.encode(
                {'node_name' : node_name,
                 'public_key_hash' : public_key_hash,
                 'passphrase' : passphrase})
        cookies = co.SimpleCookie({'user_id' : user_id, 'session_id' : session_id})
    
        return self.send_and_getter.send_and_get(self.conn, method, path, body=None, cookies=cookies)[0]
    
    
    def change_message_quota(self, user_id, session_id, node_name, new_size, when_space_exhausted, public_key_hash, passphrase=None):
    
        method = 'POST'
        path = '/proxy/message-quota'
        body = uc.encode(
                {'node_name' : node_name,
                 'new_size' : new_size,
                 'when_space_exhausted' : when_space_exhausted,
                 'public_key_hash' : public_key_hash,
                 'passphrase' : passphrase})
        cookies = co.SimpleCookie({'user_id' : user_id, 'session_id' : session_id})
    
        return self.send_and_getter.send_and_get(self.conn, method, path, body=body, cookies=cookies)[0]
    
    
    # proxy/message.wsgi
    
    def read_message(self, user_id, session_id, node_name, message_id, public_key_hash, passphrase=None):
    
        method = 'GET'
        path = '/proxy/message?' + uc.encode(
                {'node_name' : node_name,
                 'message_id' : message_id,
                 'public_key_hash' : public_key_hash,
                 'passphrase' : passphrase})
        cookies = co.SimpleCookie({'user_id' : user_id, 'session_id' : session_id})
    
        return self.send_and_getter.send_and_get(self.conn, method, path, body=None, cookies=cookies)[0]
    
    def delete_message(self, user_id, session_id, node_name, message_id, public_key_hash, passphrase=None):
    
        method = 'DELETE'
        path = '/proxy/message'
        body = uc.encode(
                {'node_name' : node_name,
                 'message_id' : message_id,
                 'public_key_hash' : public_key_hash,
                 'passphrase' : passphrase})
        cookies = co.SimpleCookie({'user_id' : user_id, 'session_id' : session_id})
    
        return self.send_and_getter.send_and_get(self.conn, method, path, body=body, cookies=cookies)[0]
    
    def send_message(self, user_id, session_id, node_name, to_user, to_user_key_hash, from_user_key_hash, message, passphrase=None):
    
        method = 'POST'
        path = '/proxy/message'
        body = uc.encode(
                {'node_name' : node_name,
                 'to_user' : to_user,
                 'to_user_key_hash' : to_user_key_hash,
                 'from_user_key_hash' : from_user_key_hash,
                 'message' : message,
                 'passphrase' : passphrase})
        cookies = co.SimpleCookie({'user_id' : user_id, 'session_id' : session_id})
    
        return self.send_and_getter.send_and_get(self.conn, method, path, body=body, cookies=cookies)[0]
    
    # proxy/node.wsgi
    
    # proxy/post-list.wsgi
    
    def read_post_list(self, user_id, session_id, node_name, group_id, owner_id, start_time, end_time, max_records, order, passphrase=None):
    
        method = 'GET'
        path = '/proxy/post-list?' + uc.encode(
                {'node_name' : node_name,
                 'group_id' : group_id,
                 'owner_id' : owner_id,
                 'start_time' : start_time,
                 'end_time' : end_time,
                 'max_records' : max_records,
                 'order' : order,
                 'passphrase' : passphrase})
        cookies = co.SimpleCookie({'user_id' : user_id, 'session_id' : session_id})
    
        return self.send_and_getter.send_and_get(self.conn, method, path, body=None, cookies=cookies)[0]
    
    
    # proxy/post.wsgi
    
    def read_post(self, user_id, session_id, node_name, group_id, owner_id, post_id, passphrase=None):
    
        method = 'GET'
        path = '/proxy/post?' + uc.encode(
                {'node_name' : node_name,
                 'group_id' : group_id,
                 'owner_id' : owner_id,
                 'post_id' : post_id,
                 'passphrase' : passphrase})
        cookies = co.SimpleCookie({'user_id' : user_id, 'session_id' : session_id})
    
        return self.send_and_getter.send_and_get(self.conn, method, path, body=None, cookies=cookies)[0]
    
    def delete_post(self, user_id, session_id, node_name, group_id, owner_id, post_id, passphrase=None):
    
        method = 'DELETE'
        path = '/proxy/post'
        body = uc.encode(
                {'node_name' : node_name,
                 'group_id' : group_id,
                 'owner_id' : owner_id,
                 'post_id' : post_id,
                 'passphrase' : passphrase})
        cookies = co.SimpleCookie({'user_id' : user_id, 'session_id' : session_id})
    
        return self.send_and_getter.send_and_get(self.conn, method, path, body=body, cookies=cookies)[0]
    
    def make_post(self, user_id, session_id, node_name, group_id, owner_id, data, passphrase=None):
    
        method = 'POST'
        path = '/proxy/post'
        body = uc.encode(
                {'node_name' : node_name,
                 'group_id' : group_id,
                 'owner_id' : owner_id,
                 'data' : data,
                 'passphrase' : passphrase})
        cookies = co.SimpleCookie({'user_id' : user_id, 'session_id' : session_id})
    
        return self.send_and_getter.send_and_get(self.conn, method, path, body=body, cookies=cookies)[0]
    
    
    # proxy/user-quota.wsgi
    
    def read_user_quota(self, user_id, session_id, node_name, public_key_hash, passphrase=None):
    
        method = 'GET'
        path = '/proxy/user-quota?' + uc.encode(
                {'node_name' : node_name,
                 'public_key_hash' : public_key_hash,
                 'passphrase' : passphrase})
        cookies = co.SimpleCookie({'user_id' : user_id, 'session_id' : session_id})
    
        return self.send_and_getter.send_and_get(self.conn, method, path, body=None, cookies=cookies)[0]
    
    
    def change_user_quota(self, user_id, session_id, node_name, new_size, user_class, auth_token, public_key_hash, passphrase=None):
    
        method = 'POST'
        path = '/proxy/user-quota'
        body = uc.encode(
                {'node_name' : node_name,
                 'new_size' : new_size,
                 'user_class' : user_class,
                 'auth_token' : auth_token,
                 'public_key_hash' : public_key_hash,
                 'passphrase' : passphrase})
        cookies = co.SimpleCookie({'user_id' : user_id, 'session_id' : session_id})
    
        return self.send_and_getter.send_and_get(self.conn, method, path, body=body, cookies=cookies)[0]
    
    
    # proxy/user.wsgi
    
    def read_user(self, user_id, session_id, node_name, public_key_hash, passphrase=None):
    
        method = 'GET'
        path = '/proxy/user?' + uc.encode(
                {'node_name' : node_name,
                 'public_key_hash' : public_key_hash,
                 'passphrase' : passphrase})
        cookies = co.SimpleCookie({'user_id' : user_id, 'session_id' : session_id})
    
        return self.send_and_getter.send_and_get(self.conn, method, path, body=None, cookies=cookies)[0]
    
    def delete_user(self, user_id, session_id, node_name, public_key_hash, passphrase=None):
    
        method = 'DELETE'
        path = '/proxy/user'
        body = uc.encode(
                {'node_name' : node_name,
                 'public_key_hash' : public_key_hash,
                 'passphrase' : passphrase})
        cookies = co.SimpleCookie({'user_id' : user_id, 'session_id' : session_id})
    
        return self.send_and_getter.send_and_get(self.conn, method, path, body=body, cookies=cookies)[0]
    
    def create_user(self, user_id, session_id,
                    node_name, public_key_hash, default_message_access, when_mail_exhausted,
                    quota_size, mail_quota_size,
                    user_class, auth_token):
    
        method = 'POST'
        path = '/proxy/user'
        body = uc.encode(
                {'node_name' : node_name,
                 'public_key_hash' : public_key_hash,
                 'default_message_access' : default_message_access,
                 'when_mail_exhausted' : when_mail_exhausted,
                 'quota_size' : quota_size,
                 'mail_quota_size' : mail_quota_size,
                 'user_class' : user_class,
                 'auth_token' : auth_token})
        cookies = co.SimpleCookie({'user_id' : user_id, 'session_id' : session_id})
    
        return self.send_and_getter.send_and_get(self.conn, method, path, body=body, cookies=cookies)[0]
    
    
    # proxy/version.wsgi
    
    def read_version(self, user_id, session_id, node_name):
    
        method = 'GET'
        path = '/proxy/version?' + uc.encode(
                {'node_name' : node_name})
        cookies = co.SimpleCookie({'user_id' : user_id, 'session_id' : session_id})
    
        return self.send_and_getter.send_and_get(self.conn, method, path, body=None, cookies=cookies)[0]
    
    
