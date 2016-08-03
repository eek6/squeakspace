#!/usr/bin/python

import httplib as ht
import json

import client_path
import client as cl
import util as ut
import client_types as tp

import test_params


conn = ht.HTTPConnection(test_params.server_address, test_params.server_port)
client = cl.Client(conn, test_params.node_name)

alf_proof_of_work_args = test_params.proof_of_work_args

user_quota = 100*1024*1024
mail_quota = 10*1024*1024
mail_quota_shrink = 1*1024*1024
mail_quota_expand = 50*1024*1024
user_quota_shrink1 = 50*1024*1024
user_quota_shrink2 = 512*1024
user_quota_expand = 200*1024*1024


key_type = test_params.key_type
if key_type == 'pgp':
    key_parameters1 = {'name_real' : 'Alf',
                       'name_email' : 'alf@example.com',
                       'key_type' : 'RSA',
                       'key_length' : 1024,
                       'key_usage' : 'cert',
                       'subkey_type' : 'RSA',
                       'subkey_length' : 1024,
                       'subkey_usage' : 'encrypt,sign,auth'}
elif key_type == 'squeak':
    key_parameters1 = {'bits' : 4096}


if key_type == 'pgp':
    key_parameters2 = {'name_real' : 'Tony',
                       'name_email' : 'tony@example.com',
                       'key_type' : 'RSA',
                       'key_length' : 1024,
                       'key_usage' : 'cert',
                       'subkey_type' : 'RSA',
                       'subkey_length' : 1024,
                       'subkey_usage' : 'encrypt,sign,auth'}
elif key_type == 'squeak':
    key_parameters2 = {'bits' : 4096}


Alf = tp.User(
        user_id='Alf',
        key=ut.createPrivateKey(key_type, key_parameters1),
        revoke_date=None,
        default_mail_access='proof_of_work/' + alf_proof_of_work_args,
        when_mail_exhausted='block',
        quota_size=user_quota,
        mail_quota_size=mail_quota,
        max_message_size=None,
        user_class=None,
        auth_token=None)

Tony = tp.User(
        user_id='Tony',
        key=ut.createPrivateKey(key_type, key_parameters2),
        revoke_date=None,
        default_mail_access='allow',
        when_mail_exhausted='block',
        quota_size=user_quota,
        mail_quota_size=mail_quota,
        max_message_size=None,
        user_class=None,
        auth_token=None)

resp = client.query_user(Alf.user_id)
assert(resp['status'] == 'ok')
assert(resp['user_exists'] == False)

resp = Alf.create(client)
assert(resp['status'] == 'ok')

if test_params.node_debug_enabled == True:
    client.send_debug({'action' : 'database'})
    client.assert_integrity(True)

resp = client.query_user(Alf.user_id)
assert(resp['status'] == 'ok')
assert(resp['user_exists'] == True)

resp = Tony.create(client)
assert(resp['status'] == 'ok')

if test_params.node_debug_enabled == True:
    client.send_debug({'action' : 'database'})
    client.assert_integrity(True)

resp = client.read_user(Alf.user_id, Alf.key)
assert(resp['status'] == 'ok')
obj = resp['user']
assert(obj['last_message_time'] == None)
if test_params.node_debug_enabled == True:
    client.assert_integrity(True)

weird_key = ut.PrivateKey(key_type, Tony.key.public_key, Tony.key.private_key, Tony.key.passphrase) 
weird_key.public_key_hash = Alf.key.public_key_hash

#resp = client.read_last_message_time(Alf.user_id, Tony.key.public_key_hash, Tony.key_type, Tony.private_key, Tony.passphrase)
resp = client.read_last_message_time(Alf.user_id, Tony.key)
assert(resp['status'] == 'error')
if test_params.node_debug_enabled == True:
    client.assert_integrity(True)

resp = client.read_last_message_time(Alf.user_id, weird_key)
#resp = client.read_last_message_time(Alf.user_id, Alf.key.public_key_hash, Tony.key_type, Tony.private_key, Tony.passphrase)
assert(resp['status'] == 'error')
if test_params.node_debug_enabled == True:
    client.assert_integrity(True)

resp = client.read_last_message_time(Alf.user_id, Alf.key)
assert(resp['status'] == 'ok')
assert(resp['last_message_time'] == None)
if test_params.node_debug_enabled == True:
    client.assert_integrity(True)


resp = client.read_user_quota(Alf.user_id, Tony.key)
assert(resp['status'] == 'error')
if test_params.node_debug_enabled == True:
    client.assert_integrity(True)

resp = client.read_user_quota(Alf.user_id, weird_key)
assert(resp['status'] == 'error')
if test_params.node_debug_enabled == True:
    client.assert_integrity(True)

resp = client.read_user_quota(Alf.user_id, Alf.key)
assert(resp['status'] == 'ok')
quota = resp['user_quota']
assert(quota['quota_allocated'] == user_quota)
if test_params.node_debug_enabled == True:
    client.assert_integrity(True)


resp = client.read_message_quota(Alf.user_id, Tony.key)
assert(resp['status'] == 'error')
if test_params.node_debug_enabled == True:
    client.assert_integrity(True)

resp = client.read_message_quota(Alf.user_id, weird_key)
assert(resp['status'] == 'error')
if test_params.node_debug_enabled == True:
    client.assert_integrity(True)

resp = client.read_message_quota(Alf.user_id, Alf.key)
assert(resp['status'] == 'ok')
quota = resp['message_quota']
assert(quota['quota_allocated'] == mail_quota)
assert(quota['quota_used'] == 0)
assert(quota['when_space_exhausted'] == 'block')
if test_params.node_debug_enabled == True:
    client.assert_integrity(True)




alf1 = 'anonymous message from alf'
alf2 = 'signed message from alf'
tony1 = 'anonymous message from tony'
tony2 = 'signed message from tony'


resp = client.set_message_access(Tony.user_id, None, 'block', Tony.key) # block anonymous mail
assert(resp['status'] == 'ok')
if test_params.node_debug_enabled == True:
    client.assert_integrity(True)


(resp, gen) = client.send_message(
        to_user=Tony.user_id,
        to_user_key_hash=Tony.key.public_key_hash,
        from_user=None,
        from_key=None,
        message=alf1,
        proof_of_work_args=None)
assert(resp['status'] == 'error')
assert(resp['reason'] == 'blocked')
(alf1_id, alf1_time, _, _, _) = gen
if test_params.node_debug_enabled == True:
    client.assert_integrity(True)


resp = client.read_max_message_size(
        to_user=Tony.user_id,
        from_user=None,
        from_key=None)
assert(resp['status'] == 'error')
assert(resp['reason'] == 'blocked')


resp = client.set_message_access(Tony.user_id, None, 'allow', Tony.key) # allow anonymous mail
assert(resp['status'] == 'ok')
if test_params.node_debug_enabled == True:
    client.assert_integrity(True)


resp = client.read_max_message_size(
        to_user=Tony.user_id,
        from_user=None,
        from_key=None)
assert(resp['status'] == 'ok')
assert(resp['max_message_size'] == None)


resp = client.change_max_message_size(
        user_id=Tony.user_id,
        new_size=1,
        auth_key=Alf.key)
assert(resp['status'] == 'error')

resp = client.change_max_message_size(
        user_id=Tony.user_id,
        new_size=1,
        auth_key=Tony.key)
assert(resp['status'] == 'ok')


(resp, gen) = client.send_message(
        to_user=Tony.user_id,
        to_user_key_hash=Tony.key.public_key_hash,
        from_user=None,
        from_key=None,
        message=alf1,
        proof_of_work_args=None)
assert(resp['status'] == 'error')
assert(resp['reason'] == 'message too large')
(alf1_id, alf1_time, _, _, _) = gen
if test_params.node_debug_enabled == True:
    client.assert_integrity(True)


resp = client.change_max_message_size(
        user_id=Tony.user_id,
        new_size=10000000,
        auth_key=Tony.key)
assert(resp['status'] == 'ok')


(resp, gen) = client.send_message(
        to_user=Tony.user_id,
        to_user_key_hash=Tony.key.public_key_hash,
        from_user=None,
        from_key=None,
        message=alf1,
        proof_of_work_args=None)
assert(resp['status'] == 'ok')
(alf1_id, alf1_time, _, _, _) = gen
if test_params.node_debug_enabled == True:
    client.assert_integrity(True)



(resp, gen) = client.send_message(
        to_user=Alf.user_id,
        to_user_key_hash=Alf.key.public_key_hash,
        from_user=None,
        from_key=None,
        message=tony1,
        proof_of_work_args=alf_proof_of_work_args)
assert(resp['status'] == 'ok')
(tony1_id, tony1_time, _, _, _) = gen
if test_params.node_debug_enabled == True:
    client.assert_integrity(True)

resp = client.read_user(Alf.user_id, Alf.key)
assert(resp['status'] == 'ok')
obj = resp['user']
assert(obj['last_message_time'] == tony1_time)
if test_params.node_debug_enabled == True:
    client.assert_integrity(True)

resp = client.read_last_message_time(Alf.user_id, Alf.key)
assert(resp['status'] == 'ok')
assert(resp['last_message_time'] == tony1_time)
if test_params.node_debug_enabled == True:
    client.assert_integrity(True)


(resp, gen) = client.send_message(
        to_user=Tony.user_id,
        to_user_key_hash=Tony.key.public_key_hash,
        from_user=Alf.user_id,
        from_key=Alf.key,
        message=alf2,
        proof_of_work_args=None)
assert(resp['status'] == 'ok')
(alf2_id, alf2_time, _, _, _) = gen
if test_params.node_debug_enabled == True:
    client.assert_integrity(True)

(resp, gen) = client.send_message(
        to_user=Alf.user_id,
        to_user_key_hash=Alf.key.public_key_hash,
        from_user=Tony.user_id,
        from_key=Tony.key,
        message=tony2,
        proof_of_work_args=alf_proof_of_work_args)
assert(resp['status'] == 'ok')
(tony2_id, tony2_time, _, _, _) = gen
if test_params.node_debug_enabled == True:
    client.assert_integrity(True)

resp = client.read_user(Alf.user_id, Alf.key)
assert(resp['status'] == 'ok')
obj = resp['user']
assert(obj['last_message_time'] == tony2_time)
if test_params.node_debug_enabled == True:
    client.assert_integrity(True)

resp = client.read_last_message_time(Alf.user_id, Alf.key)
assert(resp['status'] == 'ok')
assert(resp['last_message_time'] == tony2_time)
if test_params.node_debug_enabled == True:
    client.assert_integrity(True)


resp = client.read_message(Alf.user_id, tony1_id, Alf.key)
assert(resp['status'] == 'ok')
message = resp['message']
assert(message['message'] == tony1)
assert(message['message_id'] == tony1_id)
assert(message['timestamp'] == tony1_time)
if test_params.node_debug_enabled == True:
    client.assert_integrity(True)

resp = client.read_message(Tony.user_id, alf2_id, Tony.key)
assert(resp['status'] == 'ok')
message = resp['message']
assert(message['message'] == alf2)
assert(message['message_id'] == alf2_id)
assert(message['timestamp'] == alf2_time)
if test_params.node_debug_enabled == True:
    client.assert_integrity(True)


# Tony tries to check Alf's mail.
resp = client.read_message_list(Alf.user_id,
        to_user_key = None,
        from_user = None,
        from_user_key = None,
        start_time = tony1_time,
        end_time = tony2_time,
        max_records=None,
        order=None,
        auth_key=Tony.key)
assert(resp['status'] == 'error')
if test_params.node_debug_enabled == True:
    client.assert_integrity(True)


resp = client.read_message_list(Alf.user_id,
        to_user_key = None,
        from_user = None,
        from_user_key = None,
        start_time = tony1_time,
        end_time = tony2_time,
        max_records=None,
        order=None,
        auth_key=Alf.key)
assert(resp['status'] == 'ok')
message_list = resp['message_list']
assert(len(message_list) == 2)
if test_params.node_debug_enabled == True:
    client.assert_integrity(True)

resp = client.read_message_list(Alf.user_id,
        to_user_key = None,
        from_user = None,
        from_user_key = None,
        start_time = tony1_time,
        end_time = tony2_time,
        max_records=None,
        order='desc',
        auth_key=Alf.key)
assert(resp['status'] == 'ok')
message_list = resp['message_list']
assert(len(message_list) == 2)
if test_params.node_debug_enabled == True:
    client.assert_integrity(True)

resp = client.read_message_list(Alf.user_id,
        to_user_key = None,
        from_user = None,
        from_user_key = None,
        start_time = tony1_time,
        end_time = tony2_time,
        max_records=1,
        order='desc',
        auth_key=Alf.key)

assert(resp['status'] == 'ok')
message_list = resp['message_list']
assert(len(message_list) == 1)
if test_params.node_debug_enabled == True:
    client.assert_integrity(True)

resp = client.read_message_list(Tony.user_id,
        to_user_key = None,
        from_user = None,
        from_user_key = None,
        start_time = alf1_time,
        end_time = None,
        max_records=None,
        order='desc',
        auth_key=Tony.key)
assert(resp['status'] == 'ok')
message_list = resp['message_list']
assert(len(message_list) == 2)
if test_params.node_debug_enabled == True:
    client.assert_integrity(True)

resp = client.read_message_list(Tony.user_id,
        to_user_key = None,
        from_user = None,
        from_user_key = None,
        start_time = None,
        end_time = alf2_time,
        max_records=None,
        order='desc',
        auth_key=Tony.key)
assert(resp['status'] == 'ok')
message_list = resp['message_list']
assert(len(message_list) == 2)
if test_params.node_debug_enabled == True:
    client.assert_integrity(True)

resp = client.read_message_list(Tony.user_id,
        to_user_key = None,
        from_user = None,
        from_user_key = None,
        start_time = None,
        end_time = None,
        max_records=1,
        order='desc',
        auth_key=Tony.key)
assert(resp['status'] == 'ok')
message_list = resp['message_list']
assert(len(message_list) == 1)
if test_params.node_debug_enabled == True:
    client.assert_integrity(True)


# quotas part

resp = client.read_user_quota(Alf.user_id, Alf.key)
assert(resp['status'] == 'ok')
quota = resp['user_quota']
assert(quota['quota_allocated'] == user_quota)
if test_params.node_debug_enabled == True:
    client.assert_integrity(True)

resp = client.read_message_quota(Alf.user_id, Alf.key)
assert(resp['status'] == 'ok')
quota = resp['message_quota']
assert(quota['quota_allocated'] == mail_quota)
assert(quota['quota_used'] > 0)
assert(quota['when_space_exhausted'] == 'block')
if test_params.node_debug_enabled == True:
    client.assert_integrity(True)


resp = client.change_user_quota(Alf.user_id, mail_quota + 100, None, None, Tony.key)
assert(resp['status'] == 'error')
if test_params.node_debug_enabled == True:
    client.assert_integrity(True)

#resp = client.change_user_quota(Alf.user_id, mail_quota + 100, None, None, Alf.key.public_key_hash, Tony.key_type, Tony.private_key, Tony.passphrase)
resp = client.change_user_quota(Alf.user_id, mail_quota + 100, None, None, weird_key)
assert(resp['status'] == 'error')
if test_params.node_debug_enabled == True:
    client.assert_integrity(True)

resp = client.change_user_quota(Alf.user_id, -5, None, None, Alf.key)
assert(resp['status'] == 'error')
if test_params.node_debug_enabled == True:
    client.assert_integrity(True)

resp = client.change_user_quota(Alf.user_id, mail_quota - 100, None, None, Alf.key)
assert(resp['status'] == 'error')
if test_params.node_debug_enabled == True:
    client.assert_integrity(True)

resp = client.change_user_quota(Alf.user_id, mail_quota + 1000, None, None, Alf.key)
assert(resp['status'] == 'ok')
if test_params.node_debug_enabled == True:
    client.assert_integrity(True)

resp = client.read_user_quota(Alf.user_id, Alf.key)
assert(resp['status'] == 'ok')
quota = resp['user_quota']
assert(quota['quota_allocated'] == mail_quota + 1000)
if test_params.node_debug_enabled == True:
    client.assert_integrity(True)



resp = client.change_message_quota(Alf.user_id, mail_quota + 5, 'block', Tony.key)
assert(resp['status'] == 'error')
if test_params.node_debug_enabled == True:
    client.assert_integrity(True)

#resp = client.change_message_quota(Alf.user_id, mail_quota + 5, 'block', Alf.key.public_key_hash, Tony.key_type, Tony.private_key, Tony.passphrase)
resp = client.change_message_quota(Alf.user_id, mail_quota + 5, 'block', weird_key)
assert(resp['status'] == 'error')
if test_params.node_debug_enabled == True:
    client.assert_integrity(True)

resp = client.change_message_quota(Alf.user_id, -5, 'block', Alf.key)
assert(resp['status'] == 'error')
if test_params.node_debug_enabled == True:
    client.assert_integrity(True)

resp = client.change_message_quota(Alf.user_id, mail_quota + 5, 'blocky', Alf.key)
assert(resp['status'] == 'error')
if test_params.node_debug_enabled == True:
    client.assert_integrity(True)

resp = client.change_message_quota(Alf.user_id, 5, 'block', Alf.key)
assert(resp['status'] == 'error')
if test_params.node_debug_enabled == True:
    client.assert_integrity(True)

resp = client.change_message_quota(Alf.user_id, mail_quota + 5, 'block', Alf.key)
assert(resp['status'] == 'ok')
if test_params.node_debug_enabled == True:
    client.assert_integrity(True)

resp = client.read_message_quota(Alf.user_id, Alf.key)
assert(resp['status'] == 'ok')
quota = resp['message_quota']
assert(quota['quota_allocated'] == mail_quota + 5)
if test_params.node_debug_enabled == True:
    client.assert_integrity(True)

resp = client.change_message_quota(Alf.user_id, mail_quota - 5, 'block', Alf.key)
assert(resp['status'] == 'ok')
if test_params.node_debug_enabled == True:
    client.assert_integrity(True)

resp = client.read_message_quota(Alf.user_id, Alf.key)
assert(resp['status'] == 'ok')
quota = resp['message_quota']
assert(quota['quota_allocated'] == mail_quota - 5)
if test_params.node_debug_enabled == True:
    client.assert_integrity(True)


resp = client.change_user_quota(Alf.user_id, user_quota, None, None, Alf.key)
assert(resp['status'] == 'ok')
if test_params.node_debug_enabled == True:
    client.assert_integrity(True)

resp = client.read_user_quota(Alf.user_id, Alf.key)
assert(resp['status'] == 'ok')
quota = resp['user_quota']
assert(quota['quota_allocated'] == user_quota)
if test_params.node_debug_enabled == True:
    client.assert_integrity(True)




resp = client.change_message_quota(Alf.user_id, mail_quota, 'block', Alf.key)
assert(resp['status'] == 'ok')
if test_params.node_debug_enabled == True:
    client.assert_integrity(True)

resp = client.read_message_quota(Alf.user_id, Alf.key)
assert(resp['status'] == 'ok')
quota = resp['message_quota']
assert(quota['quota_allocated'] == mail_quota)
if test_params.node_debug_enabled == True:
    client.assert_integrity(True)





# message-access part.

other_message = 'A more filtered message'

pow_args = json.dumps({'algorithm':'hashcash','bits':20})
access_str = 'proof_of_work/' + pow_args

resp = client.read_message_access(Alf.user_id, Tony.key.public_key_hash, Alf.key)
assert(resp['status'] == 'error')
assert(resp['reason'] == 'unknown message access')
if test_params.node_debug_enabled == True:
    client.assert_integrity(True)

resp = client.set_message_access(Alf.user_id, Tony.key.public_key_hash, access_str, Alf.key)
assert(resp['status'] == 'ok')
if test_params.node_debug_enabled == True:
    client.assert_integrity(True)

resp = client.read_message_access(Alf.user_id, Tony.key.public_key_hash, Alf.key)
assert(resp['status'] == 'ok')
access = resp['message_access']
assert(access['user_id'] == Alf.user_id)
assert(access['from_user_key_hash'] == Tony.key.public_key_hash)
assert(access['access'] == access_str)
if test_params.node_debug_enabled == True:
    client.assert_integrity(True)


(resp, gen) = client.send_message(
        to_user=Alf.user_id,
        to_user_key_hash=Alf.key.public_key_hash,
        from_user=Tony.user_id,
        from_key=Tony.key,
        message=other_message,
        proof_of_work_args=None)
assert(resp['status'] == 'error')
if test_params.node_debug_enabled == True:
    client.assert_integrity(True)

(resp, gen) = client.send_message(
        to_user=Alf.user_id,
        to_user_key_hash=Alf.key.public_key_hash,
        from_user=Tony.user_id,
        from_key=Tony.key,
        message=other_message,
        proof_of_work_args=alf_proof_of_work_args)
assert(resp['status'] == 'error')
if test_params.node_debug_enabled == True:
    client.assert_integrity(True)

(resp, gen) = client.send_message(
        to_user=Alf.user_id,
        to_user_key_hash=Alf.key.public_key_hash,
        from_user=Tony.user_id,
        from_key=Tony.key,
        message=other_message,
        proof_of_work_args=pow_args)
assert(resp['status'] == 'ok')
if test_params.node_debug_enabled == True:
    client.assert_integrity(True)


resp = client.set_message_access(Alf.user_id, Tony.key.public_key_hash, 'block', Alf.key)
assert(resp['status'] == 'ok')
if test_params.node_debug_enabled == True:
    client.assert_integrity(True)

resp = client.read_message_access(Alf.user_id, Tony.key.public_key_hash, Alf.key)
assert(resp['status'] == 'ok')
access = resp['message_access']
assert(access['user_id'] == Alf.user_id)
assert(access['from_user_key_hash'] == Tony.key.public_key_hash)
assert(access['access'] == 'block')
if test_params.node_debug_enabled == True:
    client.assert_integrity(True)

(resp, gen) = client.send_message(
        to_user=Alf.user_id,
        to_user_key_hash=Alf.key.public_key_hash,
        from_user=Tony.user_id,
        from_key=Tony.key,
        message=other_message,
        proof_of_work_args=pow_args)
assert(resp['status'] == 'error')
assert(resp['reason'] == 'blocked')
if test_params.node_debug_enabled == True:
    client.assert_integrity(True)

(resp, gen) = client.send_message(
        to_user=Alf.user_id,
        to_user_key_hash=Alf.key.public_key_hash,
        from_user=Tony.user_id,
        from_key=Tony.key,
        message=other_message,
        proof_of_work_args=alf_proof_of_work_args)
assert(resp['status'] == 'error')
assert(resp['reason'] == 'blocked')
if test_params.node_debug_enabled == True:
    client.assert_integrity(True)


resp = client.delete_message_access(Alf.user_id, Tony.key.public_key_hash, Alf.key)
assert(resp['status'] == 'ok')
if test_params.node_debug_enabled == True:
    client.assert_integrity(True)

resp = client.delete_message_access(Alf.user_id, Tony.key.public_key_hash, Alf.key)
assert(resp['status'] == 'error')
if test_params.node_debug_enabled == True:
    client.assert_integrity(True)

(resp, gen) = client.send_message(
        to_user=Alf.user_id,
        to_user_key_hash=Alf.key.public_key_hash,
        from_user=Tony.user_id,
        from_key=Tony.key,
        message=other_message,
        proof_of_work_args=alf_proof_of_work_args)
assert(resp['status'] == 'ok')
if test_params.node_debug_enabled == True:
    client.assert_integrity(True)



resp = client.delete_message(Alf.user_id, tony1_id, Alf.key)
assert(resp['status'] == 'ok')
if test_params.node_debug_enabled == True:
    client.assert_integrity(True)

resp = client.delete_message(Alf.user_id, tony1_id, Alf.key)
assert(resp['status'] == 'error')
if test_params.node_debug_enabled == True:
    client.assert_integrity(True)

resp = Alf.delete(client)
assert(resp['status'] == 'ok')
if test_params.node_debug_enabled == True:
    client.assert_integrity(True)

resp = client.delete_message(Alf.user_id, tony2_id, Alf.key)
assert(resp['status'] == 'error')
if test_params.node_debug_enabled == True:
    client.assert_integrity(True)

resp = Tony.delete(client)
assert(resp['status'] == 'ok')
if test_params.node_debug_enabled == True:
    client.assert_integrity(True)
    client.assert_db_empty()

