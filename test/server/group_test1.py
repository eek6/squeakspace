#!/usr/bin/python2.7


import httplib as ht
import json

import client_path
import squeakspace.client.client as cl
import squeakspace.common.util as ut
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
if key_type == 'dummy':
    key_parameters = {}
elif key_type == 'pgp':
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

bad_key = ut.createPrivateKey(key_type, key_parameters)


if key_type == 'dummy':
    read_key_parameters = {}
    post_key_parameters = {}
    delete_key_parameters = {}
elif key_type == 'pgp':
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
          posting_pub_key = post_key,
          reading_pub_key = read_key,
          delete_pub_key = delete_key,
          quota_allocated=200*1024*1024, # too big
          when_space_exhausted='block',
          max_post_size=None,
          auth_key=Alf.key)
assert(resp['status'] == 'error')
if test_params.node_debug_enabled == True:
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


resp = client.read_last_post_time('group1', Alf.user_id, None, None)
assert(resp['status'] == 'error')
if test_params.node_debug_enabled == True:
    client.assert_integrity(True)


resp = client.read_last_post_time('group1', Alf.user_id, post_key, None)
assert(resp['status'] == 'error')
if test_params.node_debug_enabled == True:
    client.assert_integrity(True)

resp = client.read_last_post_time('group1', Alf.user_id, read_key, None)
assert(resp['status'] == 'ok')
assert(resp['last_post_time'] == None)
if test_params.node_debug_enabled == True:
    client.assert_integrity(True)


resp = client.read_group_quota('group1', Alf.user_id, None, None)
assert(resp['status'] == 'error')
if test_params.node_debug_enabled == True:
    client.assert_integrity(True)

resp = client.read_group_quota('group1', Alf.user_id, post_key, None)
assert(resp['status'] == 'error')
if test_params.node_debug_enabled == True:
    client.assert_integrity(True)

resp = client.read_group_quota('group1', Alf.user_id, read_key, None)
assert(resp['status'] == 'ok')
quota = resp['group_quota']
assert(quota['quota_allocated'] == group_quota)
if test_params.node_debug_enabled == True:
    client.assert_integrity(True)

post1 = 'first post'
post2 = 'second post'

(resp, gen) = client.make_post('group1', Alf.user_id, post1, None, None)
assert(resp['status'] == 'error')
if test_params.node_debug_enabled == True:
    client.assert_integrity(True)

(resp, gen) = client.make_post('group1', Alf.user_id, post1, read_key, None)
assert(resp['status'] == 'error')
if test_params.node_debug_enabled == True:
    client.assert_integrity(True)

(resp, gen) = client.make_post('group1', Alf.user_id, post1, post_key, None)
assert(resp['status'] == 'error')
if test_params.node_debug_enabled == True:
    client.assert_integrity(True)


resp = client.change_group_access('group1', Alf.user_id, 'post', 'block', Alf.key)
assert(resp['status'] == 'ok')
if test_params.node_debug_enabled == True:
    client.assert_integrity(True)


(resp, gen) = client.make_post('group1', Alf.user_id, post1, post_key, proof_of_work_args)
assert(resp['status'] == 'error')
assert(resp['reason'] == 'blocked')
(post1_id, post1_timestamp, _, _, _) = gen
if test_params.node_debug_enabled == True:
    client.assert_integrity(True)


resp = client.read_max_post_size('group1', Alf.user_id, post_key)
assert(resp['status'] == 'error')
assert(resp['reason'] == 'blocked')
if test_params.node_debug_enabled == True:
    client.assert_integrity(True)


resp = client.change_group_access('group1', Alf.user_id, 'post', 'allow', Alf.key)
assert(resp['status'] == 'ok')
if test_params.node_debug_enabled == True:
    client.assert_integrity(True)


resp = client.read_max_post_size('group1', Alf.user_id, None)
assert(resp['status'] == 'error')
if test_params.node_debug_enabled == True:
    client.assert_integrity(True)

resp = client.read_max_post_size('group1', Alf.user_id, post_key)
assert(resp['status'] == 'ok')
assert(resp['max_post_size'] == None)
if test_params.node_debug_enabled == True:
    client.assert_integrity(True)

resp = client.change_max_post_size('group1', Alf.user_id, 1, Alf.key)
assert(resp['status'] == 'ok')
if test_params.node_debug_enabled == True:
    client.assert_integrity(True)

resp = client.read_max_post_size('group1', Alf.user_id, post_key)
assert(resp['status'] == 'ok')
assert(resp['max_post_size'] == 1)
if test_params.node_debug_enabled == True:
    client.assert_integrity(True)


(resp, gen) = client.make_post('group1', Alf.user_id, post1, post_key, proof_of_work_args)
assert(resp['status'] == 'error')
assert(resp['reason'] == 'post too large')
(post1_id, post1_timestamp, _, _, _) = gen
if test_params.node_debug_enabled == True:
    client.assert_integrity(True)

resp = client.change_max_post_size('group1', Alf.user_id, 1000000, Alf.key)
assert(resp['status'] == 'ok')
if test_params.node_debug_enabled == True:
    client.assert_integrity(True)


(resp, gen) = client.make_post('group1', Alf.user_id, post1, post_key, proof_of_work_args)
assert(resp['status'] == 'ok')
(post1_id, post1_timestamp, _, _, _) = gen
if test_params.node_debug_enabled == True:
    client.assert_integrity(True)

resp = client.read_last_post_time('group1', Alf.user_id, read_key, None)
assert(resp['status'] == 'ok')
assert(resp['last_post_time'] == post1_timestamp)
if test_params.node_debug_enabled == True:
    client.assert_integrity(True)


resp = client.read_group_access('group1', Alf.user_id, 'read', read_key)
assert(resp['status'] == 'ok')
assert(resp['access'] == 'allow')

resp = client.change_group_access('group1', Alf.user_id, 'read', 'block', Alf.key)
assert(resp['status'] == 'ok')

resp = client.read_group_access('group1', Alf.user_id, 'read', read_key)
assert(resp['status'] == 'ok')
assert(resp['access'] == 'block')

resp = client.read_post('group1', Alf.user_id, post1_id, read_key, None)
assert(resp['status'] == 'error')
if test_params.node_debug_enabled == True:
    client.assert_integrity(True)

resp = client.change_group_access('group1', Alf.user_id, 'read', 'allow', Alf.key)
assert(resp['status'] == 'ok')

resp = client.read_post('group1', Alf.user_id, post1_id, read_key, None)
assert(resp['status'] == 'ok')
if test_params.node_debug_enabled == True:
    client.assert_integrity(True)


resp = client.read_post('group1', Alf.user_id, post1_id, None, None)
assert(resp['status'] == 'error')
if test_params.node_debug_enabled == True:
    client.assert_integrity(True)

resp = client.change_group_key('group1', Alf.user_id, 'read', None, Alf.key)
assert(resp['status'] == 'ok')
if test_params.node_debug_enabled == True:
    client.assert_integrity(True)

resp = client.read_group_key('group1', Alf.user_id, 'read', Alf.key)
assert(resp['status'] == 'ok')
assert(resp['group_key']['key_type'] == None)
assert(resp['group_key']['public_key'] == None)
if test_params.node_debug_enabled == True:
    client.assert_integrity(True)

resp = client.read_post('group1', Alf.user_id, post1_id, None, None)
assert(resp['status'] == 'ok')
if test_params.node_debug_enabled == True:
    client.assert_integrity(True)

resp = client.change_group_key('group1', Alf.user_id, 'read', read_key, Alf.key)
assert(resp['status'] == 'ok')
if test_params.node_debug_enabled == True:
    client.assert_integrity(True)

resp = client.read_post('group1', Alf.user_id, post1_id, None, None)
assert(resp['status'] == 'error')
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

assert(post1_timestamp <= post2_timestamp)

resp = client.read_last_post_time('group1', Alf.user_id, read_key, None)
assert(resp['status'] == 'ok')
assert(resp['last_post_time'] == post2_timestamp)
if test_params.node_debug_enabled == True:
    client.assert_integrity(True)


resp = client.read_post('group1', Alf.user_id, post2_id, None, None)
assert(resp['status'] == 'error')
if test_params.node_debug_enabled == True:
    client.assert_integrity(True)

resp = client.read_post('group1', Alf.user_id, post2_id, post_key, None)
assert(resp['status'] == 'error')
if test_params.node_debug_enabled == True:
    client.assert_integrity(True)

resp = client.read_post('group1', Alf.user_id, post2_id, read_key, None)
assert(resp['status'] == 'ok')
obj = resp['post']
assert(obj['post_id'] == post2_id)
assert(obj['timestamp'] == post2_timestamp)
assert(obj['data'] == post2)
if test_params.node_debug_enabled == True:
    client.assert_integrity(True)

resp = client.read_post_list('group1', Alf.user_id,
        start_time=post1_timestamp,
        end_time=post2_timestamp,
        max_records=None,
        order=None,
        group_read_key=None,
        proof_of_work_args=None)
assert(resp['status'] == 'error')
if test_params.node_debug_enabled == True:
    client.assert_integrity(True)

resp = client.read_post_list('group1', Alf.user_id,
        start_time=post1_timestamp,
        end_time=post2_timestamp,
        max_records=None,
        order=None,
        group_read_key=post_key,
        proof_of_work_args=None)
assert(resp['status'] == 'error')
if test_params.node_debug_enabled == True:
    client.assert_integrity(True)

resp = client.read_post_list('group1', Alf.user_id,
        start_time=post1_timestamp,
        end_time=post2_timestamp,
        max_records=None,
        order=None,
        group_read_key=read_key,
        proof_of_work_args=None)
assert(resp['status'] == 'ok')
if test_params.node_debug_enabled == True:
    client.assert_integrity(True)

resp = client.read_post_list('group1', Alf.user_id,
        start_time=post1_timestamp,
        end_time=post2_timestamp,
        max_records=None,
        order='desc',
        group_read_key=read_key,
        proof_of_work_args=None)
assert(resp['status'] == 'ok')
if test_params.node_debug_enabled == True:
    client.assert_integrity(True)

resp = client.read_post_list('group1', Alf.user_id,
        start_time=post1_timestamp,
        end_time=post2_timestamp,
        max_records=1,
        order='desc',
        group_read_key=read_key,
        proof_of_work_args=None)
assert(resp['status'] == 'ok')
if test_params.node_debug_enabled == True:
    client.assert_integrity(True)


resp = client.read_group_quota('group1', Alf.user_id, read_key, None)
assert(resp['status'] == 'ok')
quota = resp['group_quota']
assert(quota['quota_allocated'] == group_quota)
if test_params.node_debug_enabled == True:
    client.assert_integrity(True)


weird_key = ut.PrivateKey(bad_key.key_type, bad_key.public_key, bad_key.private_key, bad_key.passphrase)
weird_key.public_key_hash = 'bad key hash'
#resp = client.change_group_quota('group1', Alf.user_id, group_quota - 100, 'block', 'bad key hash', Alf.key_type, bad_priv_key, Alf.passphrase)
resp = client.change_group_quota('group1', Alf.user_id, group_quota - 100, 'block', weird_key)
assert(resp['status'] == 'error')
if test_params.node_debug_enabled == True:
    client.assert_integrity(True)

weird_key.public_key_hash = Alf.key.public_key_hash
#resp = client.change_group_quota('group1', Alf.user_id, group_quota - 100, 'block', Alf.public_key_hash, Alf.key_type, bad_priv_key, Alf.passphrase)
resp = client.change_group_quota('group1', Alf.user_id, group_quota - 100, 'block', weird_key)
assert(resp['status'] == 'error')
if test_params.node_debug_enabled == True:
    client.assert_integrity(True)


resp = client.change_group_quota('group1', Alf.user_id, -100, 'block', Alf.key)
assert(resp['status'] == 'error')
if test_params.node_debug_enabled == True:
    client.assert_integrity(True)


resp = client.change_group_quota('group1', Alf.user_id, 2, 'block', Alf.key)
assert(resp['status'] == 'error')
if test_params.node_debug_enabled == True:
    client.assert_integrity(True)

resp = client.change_group_quota('group1', Alf.user_id, user_quota + 100, 'block', Alf.key)
assert(resp['status'] == 'error')
if test_params.node_debug_enabled == True:
    client.assert_integrity(True)

resp = client.change_group_quota('group1', Alf.user_id, group_quota - 100, 'blocky', Alf.key)
assert(resp['status'] == 'error')
if test_params.node_debug_enabled == True:
    client.assert_integrity(True)

resp = client.change_group_quota('group1', Alf.user_id, group_quota - 100, 'block', Alf.key)
assert(resp['status'] == 'ok')
if test_params.node_debug_enabled == True:
    client.assert_integrity(True)

resp = client.read_group_quota('group1', Alf.user_id, read_key, None)
assert(resp['status'] == 'ok')
quota = resp['group_quota']
assert(quota['quota_allocated'] == group_quota - 100)
if test_params.node_debug_enabled == True:
    client.assert_integrity(True)


resp = client.change_group_quota('group1', Alf.user_id, group_quota, 'block', Alf.key)
assert(resp['status'] == 'ok')
if test_params.node_debug_enabled == True:
    client.assert_integrity(True)

resp = client.read_group_quota('group1', Alf.user_id, read_key, None)
assert(resp['status'] == 'ok')
quota = resp['group_quota']
assert(quota['quota_allocated'] == group_quota)
if test_params.node_debug_enabled == True:
    client.assert_integrity(True)



resp = client.delete_post('group1', Alf.user_id, post2_id, None, None)
assert(resp['status'] == 'error')
if test_params.node_debug_enabled == True:
    client.assert_integrity(True)

resp = client.delete_post('group1', Alf.user_id, post2_id, read_key, None)
assert(resp['status'] == 'error')
if test_params.node_debug_enabled == True:
    client.assert_integrity(True)

resp = client.delete_post('group1', Alf.user_id, post2_id, delete_key, None)
assert(resp['status'] == 'ok')
if test_params.node_debug_enabled == True:
    client.assert_integrity(True)

resp = client.delete_post('group1', Alf.user_id, post2_id, delete_key, None)
assert(resp['status'] == 'error')
if test_params.node_debug_enabled == True:
    client.assert_integrity(True)


resp = client.delete_group('group1', Alf.user_id, Alf.key)
assert(resp['status'] == 'ok')
if test_params.node_debug_enabled == True:
    client.assert_integrity(True)

resp = client.delete_group('group1', Alf.user_id, Alf.key)
assert(resp['status'] == 'error')
if test_params.node_debug_enabled == True:
    client.assert_integrity(True)

resp = Alf.delete(client)
assert(resp['status'] == 'ok')

if test_params.node_debug_enabled == True:
    client.assert_db_empty()
    client.assert_integrity(True)


resp = client.delete_group('group1', Alf.user_id, Alf.key)
assert(resp['status'] == 'error')
if test_params.node_debug_enabled == True:
    client.assert_db_empty()
    client.assert_integrity(True)

