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

user1 = 'alice'
pass1 = 'secret_password'
passphrase1 = 'secret_passphrase'
last_message_time1 = None


user2 = 'bob'
pass2 = 'passw0rd'
passphrase2 = 'secret_passphrase'
last_message_time2 = None


message1 = "hello bob"
message2 = "hello alice"
spam_message = "spam"


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

resp = cl.assign_user_key(user1, session1, test_params.node_name, pkh1)
assert(resp['status'] == 'ok')


resp, cookies = cl.create_local_user(user2, pass2)
assert(resp['status'] == 'ok')
session2 = resp['session']['session_id']
assert(cookies['user_id'].value == user2)
assert(cookies['session_id'].value == session2)


resp = cl.generate_private_key(user2, session2, test_params.key_type, test_params.key_params,
                               revoke_date=None, passphrase=passphrase2)
assert(resp['status'] == 'ok')
pkh2 = resp['public_key_hash']

resp = cl.read_private_key(user2, session2, pkh2)
assert(resp['status'] == 'ok')

resp = cl.assign_user_key(user2, session2, test_params.node_name, pkh2)
assert(resp['status'] == 'ok')

resp = cl.list_node_addr(user1, session1)
assert(resp['status'] == 'ok')
assert(len(resp['addrs']) == 0)

resp = cl.set_node_addr(user1, session1, test_params.node_name, test_params.node_addr, test_params.node_name)
assert(resp['status'] == 'ok')

resp = cl.read_node_addr(user1, session1, test_params.node_name)
assert(resp['status'] == 'ok')
assert(resp['addr']['url'] == test_params.node_addr)

resp = cl.list_node_addr(user1, session1)
assert(resp['status'] == 'ok')
assert(len(resp['addrs']) == 1)
assert(resp['addrs'][0]['node_name'] == test_params.node_name)
assert(resp['addrs'][0]['url'] == test_params.node_addr)

resp = cl.delete_node_addr(user1, session1, test_params.node_name)
assert(resp['status'] == 'ok')

resp = cl.read_node_addr(user1, session1, test_params.node_name)
assert(resp['status'] == 'error')

resp = cl.list_node_addr(user1, session1)
assert(resp['status'] == 'ok')
assert(len(resp['addrs']) == 0)

resp = cl.set_node_addr(user1, session1, test_params.node_name, test_params.node_addr, test_params.node_name)
assert(resp['status'] == 'ok')

resp = cl.set_node_addr(user2, session2, test_params.node_name, test_params.node_addr, test_params.node_name)
assert(resp['status'] == 'ok')

resp = cl.create_user(user1, session1,
                      test_params.node_name, pkh1, 'block', 'block',
                      quota_size=100*_mb, mail_quota_size=50*_mb,
                      user_class=None, auth_token=None)
assert(resp['status'] == 'ok')
assert(resp['resp']['status'] == 'ok')


resp = cl.create_user(user2, session2,
                      test_params.node_name, pkh2, 'allow', 'block',
                      quota_size=100*_mb, mail_quota_size=50*_mb,
                      user_class=None, auth_token=None)
assert(resp['status'] == 'ok')
assert(resp['resp']['status'] == 'ok')


resp = cl.read_private_key(user1, session1, pkh1)
assert(resp['status'] == 'ok')
pkt1 = resp['key']['key_type']
pk1 = resp['key']['public_key']

resp = cl.read_private_key(user2, session2, pkh2)
assert(resp['status'] == 'ok')
pkt2 = resp['key']['key_type']
pk2 = resp['key']['public_key']


resp = cl.import_public_key(user1, session1, pkt2, pk2, None)
assert(resp['status'] == 'ok')
assert(resp['public_key_hash'] == pkh2)


resp = cl.import_public_key(user2, session2, pkt1, pk1, None)
assert(resp['status'] == 'ok')
assert(resp['public_key_hash'] == pkh1)

resp = cl.assign_other_user_key(user1, session1, user2, test_params.node_name, pkh2, 5)
assert(resp['status'] == 'ok')

resp = cl.assign_other_user_key(user2, session2, user1, test_params.node_name, pkh1, 5)
assert(resp['status'] == 'ok')


resp = cl.read_last_message_time(user1, session1, test_params.node_name, pkh1, None)
#assert(resp['status'] == 'error') # fails because of dummy keys

resp = cl.cache_passphrase(user1, session1, pkh1, passphrase1, None)
assert(resp['status'] == 'ok')

resp = cl.read_last_message_time(user1, session1, test_params.node_name, pkh1, None)
assert(resp['status'] == 'ok')

resp = cl.delete_passphrase(user1, session1, None)
assert(resp['status'] == 'ok')

resp = cl.read_last_message_time(user1, session1, test_params.node_name, pkh1, None)
#assert(resp['status'] == 'error') # fails because of dummy keys



resp = cl.read_last_message_time(user1, session1, test_params.node_name, pkh1, passphrase1)
assert(resp['status'] == 'ok')
new_time = resp['resp']['last_message_time']
assert(new_time == None)
last_message_time1 = new_time



plain_part = json.dumps({'to_user' : user2,
                         'from_user' : user1,
                         'message' : message1})

resp = cl.sign(user1, session1, pkh1, plain_part, passphrase1)
assert(resp['status'] == 'ok')
sig1 = resp['signature']

plain = json.dumps(
        {'message' : plain_part,
         'from_user_key_hash' : pkh1,
         'signature' : sig1})


resp = cl.encrypt(user1, session1, pkh2, plain)
assert(resp['status'] == 'ok')
cipher = resp['ciphertext']

resp = cl.query_message_access(user1, session1, test_params.node_name, user2, None, None)
assert(resp['status'] == 'ok')

resp = cl.query_message_access(user1, session1, test_params.node_name, user2, pkh1, None)
assert(resp['status'] == 'ok')

resp = cl.send_message(user1, session1, test_params.node_name,
                       to_user=user2,
                       to_user_key_hash=pkh2,
                       from_user_key_hash=None,
                       message=cipher,
                       passphrase=None)
assert(resp['status'] == 'ok')
assert(resp['resp']['status'] == 'ok')
message1_id = resp['message_id']


resp = cl.read_last_message_time(user2, session2, test_params.node_name, pkh2, passphrase2)
assert(resp['status'] == 'ok')
assert(resp['resp']['status'] == 'ok')
new_time = resp['resp']['last_message_time']
assert(new_time != None)
last_message_time2 = new_time


resp = cl.read_message_list(user2, session2, test_params.node_name,
                            start_time=last_message_time2,
                            end_time=None,
                            max_records=None,
                            order=None,
                            public_key_hash=pkh2,
                            passphrase=passphrase2)
assert(resp['status'] == 'ok')
assert(resp['resp']['status'] == 'ok')
message_list = resp['resp']['message_list']
assert(len(message_list) == 1)
message_header = message_list[0]
assert(message_header['message_id'] == message1_id)


resp = cl.read_message(user2, session2, test_params.node_name, message1_id, pkh2, passphrase2)
assert(resp['status'] == 'ok')
assert(resp['resp']['status'] == 'ok')
assert(resp['resp']['message']['message_id'] == message1_id)
to_key_hash = resp['resp']['message']['to_user_key']
cipher = resp['resp']['message']['message']
assert(to_key_hash == pkh2)

resp = cl.decrypt(user2, session2, pkh2, cipher, passphrase2)
assert(resp['status'] == 'ok')
plain = resp['plaintext']

plain_obj = json.loads(plain)

plain_part = plain_obj['message']
from_key_hash = plain_obj['from_user_key_hash']
signature = plain_obj['signature']

resp = cl.verify_signature(user2, session2, from_key_hash, plain_part, signature)
assert(resp['status'] == 'ok')
assert(resp['valid'] == True)

plain_part_obj = json.loads(plain_part)

assert(plain_part_obj['message'] == message1) 
assert(plain_part_obj['to_user'] == user2)
assert(plain_part_obj['from_user'] == user1)



resp = cl.send_message(user2, session2, test_params.node_name,
                       to_user=user1,
                       to_user_key_hash=None,
                       from_user_key_hash=None,
                       message=message2,
                       passphrase=None)
assert(resp['status'] == 'ok')
assert(resp['resp']['status'] == 'error')
assert(resp['resp']['reason'] == 'blocked')


resp = cl.set_message_access(user1, session1, test_params.node_name, pkh2, 'allow', pkh1, passphrase1)
assert(resp['status'] == 'ok')
assert(resp['resp']['status'] == 'ok')


resp = cl.send_message(user2, session2, test_params.node_name,
                       to_user=user1,
                       to_user_key_hash=None,
                       from_user_key_hash=None,
                       message=message2,
                       passphrase=None)
assert(resp['status'] == 'ok')
assert(resp['resp']['status'] == 'error')
assert(resp['resp']['reason'] == 'blocked')


resp = cl.send_message(user2, session2, test_params.node_name,
                       to_user=user1,
                       to_user_key_hash=None,
                       from_user_key_hash=pkh2,
                       message=message2,
                       passphrase=passphrase2)
assert(resp['status'] == 'ok')
assert(resp['resp']['status'] == 'ok')
message2_id = resp['message_id']

resp = cl.read_last_message_time(user1, session1, test_params.node_name, pkh1, passphrase1)
assert(resp['status'] == 'ok')
assert(resp['resp']['status'] == 'ok')
new_time = resp['resp']['last_message_time']
assert(new_time != None)
assert(new_time > last_message_time2)
last_message_time1 = new_time

resp = cl.read_message_list(user1, session1, test_params.node_name,
                            start_time=last_message_time1,
                            end_time=None,
                            max_records=None,
                            order=None,
                            public_key_hash=pkh1,
                            passphrase=passphrase1)
assert(resp['status'] == 'ok')
assert(resp['resp']['status'] == 'ok')
message_list = resp['resp']['message_list']
assert(len(message_list) == 1)
message_header = message_list[0]
assert(message_header['message_id'] == message2_id)

resp = cl.read_message(user1, session1, test_params.node_name, message2_id, pkh1, passphrase1)
assert(resp['status'] == 'ok')
assert(resp['resp']['status'] == 'ok')
assert(resp['resp']['message']['message_id'] == message2_id)
message = resp['resp']['message']['message']
assert(message == message2)


resp = cl.delete_message_access(user1, session1, test_params.node_name, pkh2, pkh1, passphrase1)
assert(resp['status'] == 'ok')
assert(resp['resp']['status'] == 'ok')

resp = cl.send_message(user2, session2, test_params.node_name,
                       to_user=user1,
                       to_user_key_hash=None,
                       from_user_key_hash=pkh2,
                       message=spam_message,
                       passphrase=passphrase2)
assert(resp['status'] == 'ok')
assert(resp['resp']['status'] == 'error')
assert(resp['resp']['reason'] == 'blocked')


# set default access to allow.
resp = cl.set_message_access(user1, session1, test_params.node_name, None, 'allow', pkh1, passphrase1)
assert(resp['status'] == 'ok')
assert(resp['resp']['status'] == 'ok')

resp = cl.send_message(user2, session2, test_params.node_name,
                       to_user=user1,
                       to_user_key_hash=None,
                       from_user_key_hash=pkh2,
                       message=spam_message,
                       passphrase=passphrase2)
assert(resp['status'] == 'ok')
assert(resp['resp']['status'] == 'ok')



resp = cl.delete_user(user1, session1, test_params.node_name, pkh1, passphrase1)
assert(resp['status'] == 'ok')
assert(resp['resp']['status'] == 'ok')

resp = cl.delete_user(user2, session2, test_params.node_name, pkh2, passphrase2)
assert(resp['status'] == 'ok')
assert(resp['resp']['status'] == 'ok')

resp, cookies = cl.delete_local_user(user1, session1)
print cookies
assert(resp['status'] == 'ok')

resp, cookies = cl.delete_local_user(user2, session2)
print cookies
assert(resp['status'] == 'ok')

print(cl.read_local_version())

cl.assert_db_empty()


