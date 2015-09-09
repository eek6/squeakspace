#!/usr/bin/python

import httplib as ht

import client_path
import client as cl
import util as ut

import test_params

conn = ht.HTTPConnection(test_params.server_address, test_params.server_port)
client = cl.Client(conn, test_params.node_name)

user_id = 'Alf'

#key_type = 'dummy'
#key_parameters = {}

key_type = test_params.key_type
key_parameters = {'name_real' : 'Alf',
                  'name_email' : 'alf@example.com',
                  'key_type' : 'RSA',
                  'key_length' : 1024,
                  'key_usage' : 'cert',
                  'subkey_type' : 'RSA',
                  'subkey_length' : 1024,
                  'subkey_usage' : 'encrypt,sign,auth'}


user_key = ut.createPrivateKey(key_type, key_parameters)
revoke_date = None
default_mail_access = 'allow'
when_mail_exhausted = 'block'
quota_size = 100*1024*1024
mail_quota_size = 10*1024*1024
user_class = None
auth_token = None


resp = client.create_user(
        user_id, user_key, revoke_date,
        default_mail_access, when_mail_exhausted,
        quota_size, mail_quota_size,
        user_class, auth_token)
assert(resp['status'] == 'ok')

print (client.send_debug({'action' : 'database'}))
client.assert_integrity(True)

resp = client.delete_user(user_id, user_key)
assert(resp['status'] == 'ok')

client.assert_db_empty()
client.assert_integrity(True)

