#!/usr/bin/python

import httplib as ht
import json

import client_path
import client as cl
import util as ut
import client_types as tp

import test_params

# This tests the free_oldest value for when_space_exhausted in the mail_quota.
# Old messages should be automatically deleted by the server
# to make space for new messages when space is exhausted.


conn = ht.HTTPConnection(test_params.server_address, test_params.server_port)
client = cl.Client(conn, test_params.node_name)

alf_proof_of_work_args = test_params.proof_of_work_args

user_quota = 100*1024*1024
mail_quota = 10*1024*1024


key_type = test_params.key_type
key_parameters1 = {'name_real' : 'Alf',
                   'name_email' : 'alf@example.com',
                   'key_type' : 'RSA',
                   'key_length' : 1024,
                   'key_usage' : 'cert',
                   'subkey_type' : 'RSA',
                   'subkey_length' : 1024,
                   'subkey_usage' : 'encrypt,sign,auth'}


key_parameters2 = {'name_real' : 'Tony',
                   'name_email' : 'tony@example.com',
                   'key_type' : 'RSA',
                   'key_length' : 1024,
                   'key_usage' : 'cert',
                   'subkey_type' : 'RSA',
                   'subkey_length' : 1024,
                   'subkey_usage' : 'encrypt,sign,auth'}


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


resp = Alf.create(client)
assert(resp['status'] == 'ok')
client.send_debug({'action' : 'database'})
client.assert_integrity(True)

resp = Tony.create(client)
assert(resp['status'] == 'ok')
client.send_debug({'action' : 'database'})
client.assert_integrity(True)


message1 = '1' * (mail_quota / 4)
message2 = '2' * (mail_quota / 4)
message3 = '3' * (mail_quota / 4)
message4 = '4' * (mail_quota / 4)
message5 = '5' * (mail_quota / 4)


(resp, gen) = client.send_message(
        to_user=Tony.user_id,
        to_user_key_hash=Tony.key.public_key_hash,
        from_user=None,
        from_key=None,
        message=message1,
        proof_of_work_args=None)
assert(resp['status'] == 'ok')
(mes1_id, mes1_time, _, _, _) = gen
client.assert_integrity(True)


(resp, gen) = client.send_message(
        to_user=Tony.user_id,
        to_user_key_hash=Tony.key.public_key_hash,
        from_user=None,
        from_key=None,
        message=message2,
        proof_of_work_args=None)
assert(resp['status'] == 'ok')
(mes2_id, mes2_time, _, _, _) = gen
client.assert_integrity(True)


(resp, gen) = client.send_message(
        to_user=Tony.user_id,
        to_user_key_hash=Tony.key.public_key_hash,
        from_user=None,
        from_key=None,
        message=message3,
        proof_of_work_args=None)
assert(resp['status'] == 'ok')
(mes3_id, mes3_time, _, _, _) = gen
client.assert_integrity(True)


(resp, gen) = client.send_message(
        to_user=Tony.user_id,
        to_user_key_hash=Tony.key.public_key_hash,
        from_user=None,
        from_key=None,
        message=message4,
        proof_of_work_args=None)
assert(resp['status'] == 'error')
assert(resp['reason'] == 'quota exceeded')
(mes4_id, mes4_time, _, _, _) = gen
client.assert_integrity(True)


resp = client.read_user_quota(Tony.user_id, Tony.key)
assert(resp['status'] == 'ok')
quota = resp['user_quota']
assert(quota['quota_allocated'] == user_quota)
client.assert_integrity(True)

resp = client.read_message_quota(Tony.user_id, Tony.key)
assert(resp['status'] == 'ok')
quota = resp['message_quota']
assert(quota['quota_allocated'] == mail_quota)
assert(quota['quota_used'] > 0)
assert(quota['when_space_exhausted'] == 'block')
client.assert_integrity(True)


resp = client.change_message_quota(Tony.user_id, mail_quota, 'free_eldest', Tony.key)
assert(resp['status'] == 'error')
client.assert_integrity(True)

resp = client.change_message_quota(Tony.user_id, mail_quota, 'free_oldest', Tony.key)
assert(resp['status'] == 'ok')
client.assert_integrity(True)


resp = client.read_message_quota(Tony.user_id, Tony.key)
assert(resp['status'] == 'ok')
quota = resp['message_quota']
assert(quota['quota_allocated'] == mail_quota)
assert(quota['when_space_exhausted'] == 'free_oldest')
client.assert_integrity(True)


(resp, gen) = client.send_message(
        to_user=Tony.user_id,
        to_user_key_hash=Tony.key.public_key_hash,
        from_user=None,
        from_key=None,
        message=message4,
        proof_of_work_args=None)
assert(resp['status'] == 'ok')
(mes4_id, mes4_time, _, _, _) = gen
client.assert_integrity(True)

resp = client.read_message(Tony.user_id, mes4_id, Tony.key)
assert(resp['status'] == 'ok')
message = resp['message']
assert(message['message'] == message4)
assert(message['message_id'] == mes4_id)
assert(message['timestamp'] == mes4_time)
client.assert_integrity(True)


(resp, gen) = client.send_message(
        to_user=Tony.user_id,
        to_user_key_hash=Tony.key.public_key_hash,
        from_user=None,
        from_key=None,
        message=message5,
        proof_of_work_args=None)
assert(resp['status'] == 'ok')
(mes5_id, mes5_time, _, _, _) = gen
client.assert_integrity(True)

resp = client.read_message(Tony.user_id, mes5_id, Tony.key)
assert(resp['status'] == 'ok')
message = resp['message']
assert(message['message'] == message5)
assert(message['message_id'] == mes5_id)
assert(message['timestamp'] == mes5_time)
client.assert_integrity(True)


# the first message must have been automatically deleted.
resp = client.read_message(Tony.user_id, mes1_id, Tony.key)
assert(resp['status'] == 'error')
assert(resp['reason'] == 'unknown message')
client.assert_integrity(True)


resp = Alf.delete(client)
assert(resp['status'] == 'ok')
client.assert_integrity(True)

resp = Tony.delete(client)
assert(resp['status'] == 'ok')
client.assert_integrity(True)

client.assert_db_empty()

