#!/usr/bin/python

import httplib as ht

import client_path
import client

import test_params

conn = ht.HTTPConnection(test_params.server_address, test_params.server_port)

cl = client.Client(conn)

user1 = 'alice'
pass1 = 'secret_password'
passphrase1 = 'secret_passphrase'


resp, cookies = cl.create_local_user(user1, pass1)
print cookies
print cookies['user_id'].value
assert(resp['status'] == 'ok')
assert(cookies['user_id'].value == user1)
session1 = cookies['session_id'].value

resp = cl.generate_private_key(user1, session1, test_params.key_type, test_params.key_params,
                               revoke_date=None, passphrase=passphrase1)
assert(resp['status'] == 'ok')
pkh1 = resp['public_key_hash']

resp = cl.read_private_key(user1, session1, pkh1)
assert(resp['status'] == 'ok')

resp = cl.delete_private_key(user1, session1, pkh1)
assert(resp['status'] == 'ok')

resp, cookies = cl.delete_local_user(user1, session1)
print cookies
assert(resp['status'] == 'ok')

print(cl.read_local_version())

resp = cl.local_debug('database')
print resp

cl.assert_db_empty()


