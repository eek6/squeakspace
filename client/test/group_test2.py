#!/usr/bin/python


import httplib as ht
import json

import client_path
import client as cl
import util as ut
import client_types as tp

import test_params


proof_of_work_args = test_params.proof_of_work_args
alf_proof_of_work_args = test_params.bad_proof_of_work_args

conn = ht.HTTPConnection(test_params.server_address, test_params.server_port)
client = cl.Client(conn, test_params.node_name)


user_quota = 30*1024*1024
mail_quota = 10*1024*1024
group_quota = 10*1024*1024


key_type = test_params.key_type
if key_type == 'pgp':
    key_parameters = {'name_real' : 'Alf',
                      'name_email' : 'alf@example.com',
                      'key_type' : 'RSA',
                      'key_length' : 1024,
                      'key_usage' : 'cert',
                      'subkey_type' : 'RSA',
                      'subkey_length' : 1024,
                      'subkey_usage' : 'encrypt,sign,auth'}
elif key_type == 'squeak':
    key_parameters = {'bits' : 4096}


Alf = tp.User(
        user_id='Alf',
        key=ut.createPrivateKey(key_type, key_parameters),
        revoke_date=None,
        #default_mail_access='allow',
        default_mail_access='proof_of_work/' + alf_proof_of_work_args,
        when_mail_exhausted='block',
        quota_size=user_quota,
        mail_quota_size=mail_quota,
        max_message_size=None,
        user_class=None,
        auth_token=None)


if key_type == 'pgp':
    read_key_parameters = {'name_real' : 'read.group1.Alf',
                           'name_email' : 'read.group1.alf@example.com',
                           'key_type' : 'RSA',
                           'key_length' : 1024,
                           'key_usage' : 'cert',
                           'subkey_type' : 'RSA',
                           'subkey_length' : 1024,
                           'subkey_usage' : 'encrypt,sign,auth'}

    post_key_parameters = {'name_real' : 'post.group1.Alf',
                           'name_email' : 'post.group1.alf@example.com',
                           'key_type' : 'RSA',
                           'key_length' : 1024,
                           'key_usage' : 'cert',
                           'subkey_type' : 'RSA',
                           'subkey_length' : 1024,
                           'subkey_usage' : 'encrypt,sign,auth'}

    delete_key_parameters = {'name_real' : 'delete.group1.Alf',
                             'name_email' : 'delete.group1.alf@example.com',
                             'key_type' : 'RSA',
                             'key_length' : 1024,
                             'key_usage' : 'cert',
                             'subkey_type' : 'RSA',
                             'subkey_length' : 1024,
                             'subkey_usage' : 'encrypt,sign,auth'}

elif key_type == 'squeak':
    read_key_parameters = {'bits' : 4096}
    post_key_parameters = {'bits' : 4096}
    delete_key_parameters = {'bits' : 4096}


read_key = ut.createPrivateKey(key_type, read_key_parameters)
post_key = ut.createPrivateKey(key_type, post_key_parameters)
delete_key = ut.createPrivateKey(key_type, delete_key_parameters)


resp = Alf.create(client)

assert(resp['status'] == 'ok')

if test_params.node_debug_enabled == True:
    print (client.send_debug({'action' : 'database'}))
    client.assert_integrity(True)



resp = client.create_group(
          group_id='group1',
          owner_id=Alf.user_id,
          post_access='proof_of_work/' + proof_of_work_args,
          read_access='allow',
          delete_access='allow',
          posting_pub_key=post_key,
          reading_pub_key=read_key,
          delete_pub_key=delete_key,
          quota_allocated=group_quota,
          when_space_exhausted='block',
          max_post_size=None,
          auth_key=Alf.key)
assert(resp['status'] == 'ok')
if test_params.node_debug_enabled == True:
    client.assert_integrity(True)


post1 = '1' * (group_quota / 4)
post2 = '2' * (group_quota / 4)
post3 = '3' * (group_quota / 4)
post4 = '4' * (group_quota / 4)
post5 = '5' * (group_quota / 4)

(resp, gen) = client.make_post('group1', Alf.user_id, post1, post_key, proof_of_work_args)
assert(resp['status'] == 'ok')
(post1_id, post1_timestamp, _, _, _) = gen
if test_params.node_debug_enabled == True:
    client.assert_integrity(True)


resp = client.read_post('group1', Alf.user_id, post1_id, read_key, None)
assert(resp['status'] == 'ok')
if test_params.node_debug_enabled == True:
    client.assert_integrity(True)


(resp, gen) = client.make_post('group1', Alf.user_id, post2, post_key, proof_of_work_args)
assert(resp['status'] == 'ok')
(post2_id, post2_timestamp, _, _, _) = gen
if test_params.node_debug_enabled == True:
    client.assert_integrity(True)

resp = client.read_post('group1', Alf.user_id, post2_id, read_key, None)
assert(resp['status'] == 'ok')
if test_params.node_debug_enabled == True:
    client.assert_integrity(True)


(resp, gen) = client.make_post('group1', Alf.user_id, post3, post_key, proof_of_work_args)
assert(resp['status'] == 'ok')
(post3_id, post3_timestamp, _, _, _) = gen
if test_params.node_debug_enabled == True:
    client.assert_integrity(True)

resp = client.read_post('group1', Alf.user_id, post3_id, read_key, None)
assert(resp['status'] == 'ok')
if test_params.node_debug_enabled == True:
    client.assert_integrity(True)


(resp, gen) = client.make_post('group1', Alf.user_id, post4, post_key, proof_of_work_args)
assert(resp['status'] == 'error')
assert(resp['reason'] == 'quota exceeded')
(post3_id, post3_timestamp, _, _, _) = gen
if test_params.node_debug_enabled == True:
    client.assert_integrity(True)


resp = client.read_group_quota('group1', Alf.user_id, read_key, None)
assert(resp['status'] == 'ok')
quota = resp['group_quota']
assert(quota['quota_allocated'] == group_quota)
assert(quota['when_space_exhausted'] == 'block')
if test_params.node_debug_enabled == True:
    client.assert_integrity(True)


resp = client.change_group_quota('group1', Alf.user_id, group_quota, 'FREE_OLDEST', Alf.key)
assert(resp['status'] == 'error')
if test_params.node_debug_enabled == True:
    client.assert_integrity(True)

resp = client.change_group_quota('group1', Alf.user_id, group_quota, 'free_oldest', Alf.key)
assert(resp['status'] == 'ok')
if test_params.node_debug_enabled == True:
    client.assert_integrity(True)

resp = client.read_group_quota('group1', Alf.user_id, read_key, None)
assert(resp['status'] == 'ok')
quota = resp['group_quota']
assert(quota['quota_allocated'] == group_quota)
assert(quota['when_space_exhausted'] == 'free_oldest')
if test_params.node_debug_enabled == True:
    client.assert_integrity(True)


(resp, gen) = client.make_post('group1', Alf.user_id, post4, post_key, proof_of_work_args)
assert(resp['status'] == 'ok')
(post4_id, post4_timestamp, _, _, _) = gen
if test_params.node_debug_enabled == True:
    client.assert_integrity(True)

resp = client.read_post('group1', Alf.user_id, post4_id, read_key, None)
assert(resp['status'] == 'ok')
if test_params.node_debug_enabled == True:
    client.assert_integrity(True)

(resp, gen) = client.make_post('group1', Alf.user_id, post5, post_key, proof_of_work_args)
assert(resp['status'] == 'ok')
(post5_id, post5_timestamp, _, _, _) = gen
if test_params.node_debug_enabled == True:
    client.assert_integrity(True)

resp = client.read_post('group1', Alf.user_id, post5_id, read_key, None)
assert(resp['status'] == 'ok')
if test_params.node_debug_enabled == True:
    client.assert_integrity(True)


resp = client.read_post('group1', Alf.user_id, post1_id, read_key, None)
assert(resp['status'] == 'error')
assert(resp['reason'] == 'unknown post')
if test_params.node_debug_enabled == True:
    client.assert_integrity(True)


resp = Alf.delete(client)
assert(resp['status'] == 'ok')
if test_params.node_debug_enabled == True:
    client.assert_integrity(True)
    client.assert_db_empty()


