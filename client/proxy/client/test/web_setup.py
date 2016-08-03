#!/usr/bin/python

import httplib as ht

import json
import client_path
import client

import test_params


_kb = 1024
_mb = 1024*_kb
_gb = 1024*_mb



conn = ht.HTTPConnection(test_params.server_address, test_params.server_port)

cl = client.Client(conn)

user1 = 'user1'
pass1 = 'user1'
passphrase1 = None
key_params1 = test_params.key_params.copy()
key_params1['passphrase'] = passphrase1

user2 = 'user2'
pass2 = 'user2'
passphrase2 = None
key_params2 = test_params.key_params.copy()
key_params2['passphrase'] = passphrase2


local_node_name = 'local'

resp, cookies = cl.create_local_user(user1, pass1)
print cookies
print cookies['user_id'].value
assert(resp['status'] == 'ok')
assert(cookies['user_id'].value == user1)
session1 = cookies['session_id'].value

resp, cookies = cl.create_local_user(user2, pass2)
print cookies
print cookies['user_id'].value
assert(resp['status'] == 'ok')
assert(cookies['user_id'].value == user2)
session2 = cookies['session_id'].value


resp = cl.generate_private_key(user1, session1, test_params.key_type, json.dumps(key_params1), revoke_date=None)
assert(resp['status'] == 'ok')
pkh1 = resp['public_key_hash']

resp = cl.read_private_key(user1, session1, pkh1)
assert(resp['status'] == 'ok')
key1 = resp['key']


resp = cl.generate_private_key(user2, session2, test_params.key_type, json.dumps(key_params2), revoke_date=None)
assert(resp['status'] == 'ok')
pkh2 = resp['public_key_hash']

resp = cl.read_private_key(user2, session2, pkh2)
assert(resp['status'] == 'ok')
key2 = resp['key']

resp = cl.import_public_key(user1, session1, key2['key_type'], key2['public_key'], key2['revoke_date'])
assert(resp['status'] == 'ok')

resp = cl.import_public_key(user2, session2, key1['key_type'], key1['public_key'], key1['revoke_date'])
assert(resp['status'] == 'ok')

resp = cl.assign_user_key(user1, session1, local_node_name, pkh1)
assert(resp['status'] == 'ok')

resp = cl.assign_user_key(user2, session2, local_node_name, pkh2)
assert(resp['status'] == 'ok')

resp = cl.set_node_addr(user1, session1, local_node_name, test_params.node_addr, test_params.node_name)
assert(resp['status'] == 'ok')

resp = cl.set_node_addr(user2, session2, local_node_name, test_params.node_addr, test_params.node_name)
assert(resp['status'] == 'ok')

resp = cl.create_user(user1, session1,
                      local_node_name, pkh1, 'block', 'block',
                      quota_size=100*_mb, mail_quota_size=50*_mb,
                      max_message_size=5*_mb,
                      user_class=None, auth_token=None)
assert(resp['status'] == 'ok')
assert(resp['resp']['status'] == 'ok')


resp = cl.create_user(user2, session2,
                      local_node_name, pkh2, 'allow', 'block',
                      quota_size=100*_mb, mail_quota_size=50*_mb,
                      max_message_size=5*_mb,
                      user_class=None, auth_token=None)
assert(resp['status'] == 'ok')
assert(resp['resp']['status'] == 'ok')

resp = cl.assign_other_user_key(user1, session1, user2, local_node_name, key2['public_key_hash'], 100)
assert(resp['status'] == 'ok')

resp = cl.assign_other_user_key(user2, session2, user1, local_node_name, key1['public_key_hash'], 100)
assert(resp['status'] == 'ok')

