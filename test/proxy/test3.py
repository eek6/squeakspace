#!/usr/bin/python2.7

import httplib as ht
import json

import client_path
import squeakspace.proxy.client.client as client

import test_params

conn = ht.HTTPConnection(test_params.server_address, test_params.server_port)

cl = client.Client(conn)

user1 = 'alice'
pass1 = 'secret_password'
passphrase1 = 'secret_passphrase'
key_params1 = test_params.key_params.copy()
key_params1['passphrase'] = passphrase1


group_name = 'alice.club'
group_passphrase = 'super secret'
group_key_params = test_params.key_params.copy()
group_key_params['passphrase'] = group_passphrase

node_name = 'deluxenode'


resp, cookies = cl.create_local_user(user1, pass1)
print cookies
print cookies['user_id'].value
assert(resp['status'] == 'ok')
assert(cookies['user_id'].value == user1)
session1 = cookies['session_id'].value

resp = cl.generate_private_key(user1, session1, test_params.key_type, json.dumps(key_params1), revoke_date=None)
assert(resp['status'] == 'ok')
pkh1 = resp['public_key_hash']

resp = cl.read_private_key(user1, session1, pkh1)
assert(resp['status'] == 'ok')

resp = cl.assign_user_key(user1, session1, node_name, pkh1)
assert(resp['status'] == 'ok')


resp = cl.generate_private_key(user1, session1, test_params.key_type, json.dumps(group_key_params), revoke_date=None)
assert(resp['status'] == 'ok')
group_key_hash = resp['public_key_hash']

resp = cl.assign_local_group_key(user1, session1, group_name, user1, node_name, 'post', group_key_hash)
assert(resp['status'] == 'ok')

resp = cl.assign_local_group_key(user1, session1, group_name, user1, node_name, 'read', group_key_hash)
assert(resp['status'] == 'ok')

resp = cl.assign_local_group_key(user1, session1, group_name, user1, node_name, 'delete', pkh1)
assert(resp['status'] == 'ok')


resp = cl.set_local_group_access(user1, session1, group_name, user1, node_name, 'post', 'allow')
assert(resp['status'] == 'ok')

resp = cl.set_local_group_access(user1, session1, group_name, user1, node_name, 'read', 'allow')
assert(resp['status'] == 'ok')

resp = cl.set_local_group_access(user1, session1, group_name, user1, node_name, 'delete', 'allow')
assert(resp['status'] == 'ok')


resp = cl.set_local_message_access(user1, session1, 'bob', node_name, pkh1, 'block')
assert(resp['status'] == 'ok')

resp = cl.read_local_message_access(user1, session1, 'bob', node_name, pkh1)
assert(resp['status'] == 'ok')
assert(resp['access']['user_id'] == user1)
assert(resp['access']['to_user'] == 'bob')
assert(resp['access']['from_user_key_hash'] == pkh1)
assert(resp['access']['access'] == 'block')

resp = cl.set_local_message_access(user1, session1, 'bob', node_name, pkh1, 'allow')
assert(resp['status'] == 'ok')

resp = cl.read_local_message_access(user1, session1, 'bob', node_name, pkh1)
assert(resp['status'] == 'ok')
assert(resp['access']['user_id'] == user1)
assert(resp['access']['to_user'] == 'bob')
assert(resp['access']['from_user_key_hash'] == pkh1)
assert(resp['access']['access'] == 'allow')

resp = cl.delete_local_message_access(user1, session1, 'bob', node_name, pkh1)
assert(resp['status'] == 'ok')

resp = cl.read_local_message_access(user1, session1, 'bob', node_name, pkh1)
assert(resp['status'] == 'error')

resp = cl.set_local_group_access(user1, session1, 'some.group', 'some.user', node_name, 'read', 'allow')
assert(resp['status'] == 'ok')

resp = cl.read_local_group_access(user1, session1, 'some.group', 'some.user', node_name, 'read')
assert(resp['status'] == 'ok')
assert(resp['access']['user_id'] == user1)
assert(resp['access']['owner_id'] == 'some.user')
assert(resp['access']['group_id'] == 'some.group')
assert(resp['access']['access'] == 'allow')

resp = cl.set_local_group_access(user1, session1, 'some.group', 'some.user', node_name, 'read', 'block')
assert(resp['status'] == 'ok')

resp = cl.read_local_group_access(user1, session1, 'some.group', 'some.user', node_name, 'read')
assert(resp['status'] == 'ok')
assert(resp['access']['user_id'] == user1)
assert(resp['access']['owner_id'] == 'some.user')
assert(resp['access']['group_id'] == 'some.group')
assert(resp['access']['access'] == 'block')

resp = cl.delete_local_group_access(user1, session1, 'some.group', 'some.user', node_name, 'read')
assert(resp['status'] == 'ok')

resp = cl.read_local_group_access(user1, session1, 'some.group', 'some.user', node_name, 'read')
assert(resp['status'] == 'error')

resp = cl.read_local_group_key(user1, session1, group_name, user1, node_name, 'read') 
assert(resp['status'] == 'ok')
assert(resp['key']['group_id'] == group_name)
assert(resp['key']['owner_id'] == user1)
assert(resp['key']['node_name'] == node_name)
assert(resp['key']['key_use'] == 'read')
assert(resp['key']['public_key_hash'] == group_key_hash)

resp = cl.delete_local_group_key(user1, session1, group_name, user1, node_name, 'read') 
assert(resp['status'] == 'ok')

resp = cl.read_local_group_key(user1, session1, group_name, user1, node_name, 'read') 
assert(resp['status'] == 'error')

resp = cl.read_user_key(user1, session1, node_name, pkh1)
assert(resp['status'] == 'ok')
assert(resp['key']['public_key_hash'] == pkh1)

resp = cl.delete_user_key(user1, session1, node_name, pkh1)
assert(resp['status'] == 'ok')

resp = cl.read_user_key(user1, session1, node_name, pkh1)
assert(resp['status'] == 'error')

resp = cl.delete_private_key(user1, session1, pkh1)
assert(resp['status'] == 'ok')

resp, cookies = cl.sign_out(user1, session1)
assert(resp['status'] == 'ok')

resp, cookies = cl.login(user1, 'bad_password')
assert(resp['status'] == 'error')

resp, cookies = cl.login(user1, pass1)
assert(resp['status'] == 'ok')
session2 = resp['session']['session_id']
assert(resp['session']['user_id'] == user1)
assert(cookies['user_id'].value == user1)
assert(cookies['session_id'].value == session2)

resp, cookies = cl.delete_local_user(user1, session2)
print cookies
assert(resp['status'] == 'ok')

print(cl.read_local_version())

if test_params.local_debug_enabled == True:
    resp = cl.local_debug('database')
    print resp

    cl.assert_db_empty()


