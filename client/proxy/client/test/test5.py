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
group_name = 'wall'
group_passphrase = 'alice-wall'
last_post_time1 = None


user2 = 'bob'
pass2 = 'passw0rd'
passphrase2 = 'secret_passphrase'
last_message_time2 = None
last_post_time2 = None


post1 = 'hello alice'
post2 = 'hello bob'
spam_post = 'spam'


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

resp = cl.read_private_key(user1, session1, pkh1, False, True)
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

resp = cl.read_private_key(user2, session2, pkh2, False, True)
assert(resp['status'] == 'ok')

resp = cl.assign_user_key(user2, session2, test_params.node_name, pkh2)
assert(resp['status'] == 'ok')


resp = cl.set_node_addr(user1, session1, test_params.node_name, test_params.node_addr, test_params.node_name)
assert(resp['status'] == 'ok')

resp = cl.read_node_addr(user1, session1, test_params.node_name)
assert(resp['status'] == 'ok')
assert(resp['addr']['url'] == test_params.node_addr)

resp = cl.delete_node_addr(user1, session1, test_params.node_name)
assert(resp['status'] == 'ok')

resp = cl.read_node_addr(user1, session1, test_params.node_name)
assert(resp['status'] == 'error')

resp = cl.set_node_addr(user1, session1, test_params.node_name, test_params.node_addr, test_params.node_name)
assert(resp['status'] == 'ok')

resp = cl.set_node_addr(user2, session2, test_params.node_name, test_params.node_addr, test_params.node_name)
assert(resp['status'] == 'ok')

resp = cl.create_user(user1, session1,
                      test_params.node_name, pkh1, 'block', 'block',
                      quota_size=100*_mb, mail_quota_size=50*_mb,
                      max_message_size=None,
                      user_class=None, auth_token=None)
assert(resp['status'] == 'ok')
assert(resp['resp']['status'] == 'ok')


resp = cl.create_user(user2, session2,
                      test_params.node_name, pkh2, 'allow', 'block',
                      quota_size=100*_mb, mail_quota_size=50*_mb,
                      max_message_size=None,
                      user_class=None, auth_token=None)
assert(resp['status'] == 'ok')
assert(resp['resp']['status'] == 'ok')


resp = cl.read_private_key(user1, session1, pkh1, False, True)
assert(resp['status'] == 'ok')
pkt1 = resp['key']['key_type']
pk1 = resp['key']['public_key']

resp = cl.read_private_key(user2, session2, pkh2, False, True)
assert(resp['status'] == 'ok')
pkt2 = resp['key']['key_type']
pk2 = resp['key']['public_key']


resp = cl.import_public_key(user1, session1, pkt2, pk2, None)
assert(resp['status'] == 'ok')
assert(resp['public_key_hash'] == pkh2)


resp = cl.import_public_key(user2, session2, pkt1, pk1, None)
assert(resp['status'] == 'ok')
assert(resp['public_key_hash'] == pkh1)



## alice creates a group

resp = cl.generate_private_key(user1, session1, test_params.key_type, test_params.key_params,
                               revoke_date=None, passphrase=passphrase1)
assert(resp['status'] == 'ok')
group_pkh = resp['public_key_hash']

resp = cl.read_private_key(user1, session1, group_pkh, False, True)
assert(resp['status'] == 'ok')
group_pkt = resp['key']['key_type']
group_pk = resp['key']['public_key']
group_prk = resp['key']['private_key']
assert(resp['key']['public_key_hash'] == group_pkh)


group_post_access = 'proof_of_work/' + test_params.proof_of_work_args


# Now these are assigned within the creat_group request which has
# the side effect of caching the values locally.
#
#resp = cl.assign_local_group_key(user1, session1, group_name, user1, test_params.node_name, 'read', group_pkh)
#assert(resp['status'] == 'ok')
#
#resp = cl.assign_local_group_key(user1, session1, group_name, user1, test_params.node_name, 'post', group_pkh)
#assert(resp['status'] == 'ok')
#
#resp = cl.assign_local_group_key(user1, session1, group_name, user1, test_params.node_name, 'delete', pkh1)
#assert(resp['status'] == 'ok')
#
#resp = cl.set_local_group_access(user1, session1, group_name, user1, test_params.node_name, 'read', 'allow')
#assert(resp['status'] == 'ok')
#
#resp = cl.set_local_group_access(user1, session1, group_name, user1, test_params.node_name, 'post', group_post_access)
#assert(resp['status'] == 'ok')
#
#resp = cl.set_local_group_access(user1, session1, group_name, user1, test_params.node_name, 'delete', 'allow')
#assert(resp['status'] == 'ok')


resp = cl.create_group(user1, session1, test_params.node_name, group_name,
                       post_access=group_post_access,
                       read_access='allow',
                       delete_access='allow',
                       posting_key_hash=group_pkh,
                       reading_key_hash=group_pkh,
                       delete_key_hash=pkh1,
                       quota_allocated=10*_mb,
                       when_space_exhausted='block',
                       max_post_size=None,
                       public_key_hash=pkh1,
                       passphrase=passphrase1)
assert(resp['status'] == 'ok')
assert(resp['resp']['status'] == 'ok')


resp = cl.change_group_quota(user1, session1, test_params.node_name, group_name,
                             new_size=20*_mb,
                             when_space_exhausted='block',
                             public_key_hash=pkh1,
                             passphrase=passphrase1)
assert(resp['status'] == 'ok')
assert(resp['resp']['status'] == 'ok')

resp = cl.read_group_quota(user1, session1, test_params.node_name, group_name, user1, group_passphrase)
assert(resp['status'] == 'ok')
assert(resp['resp']['status'] == 'ok')
assert(resp['resp']['group_quota']['quota_allocated'] == 20*_mb)
assert(resp['resp']['group_quota']['when_space_exhausted'] == 'block')


resp = cl.change_group_quota(user1, session1, test_params.node_name, group_name,
                             new_size=20*_gb,
                             when_space_exhausted='block',
                             public_key_hash=pkh1,
                             passphrase=passphrase1)
assert(resp['status'] == 'ok')
assert(resp['resp']['status'] == 'error')



# Now invite bob to the group.


resp = cl.read_last_message_time(user1, session1, test_params.node_name, pkh1, passphrase1)
assert(resp['status'] == 'ok')
new_time = resp['resp']['last_message_time']
assert(new_time == None)
last_message_time1 = new_time


invitation = {'type' : 'local_command_sequence',
              'commands' : [{'type' : 'private_key',
                             'key_type' : group_pkt,
                             'public_key' : group_pk,
                             'private_key' : group_prk,
                             'public_key_hash' : group_pkh,
                             'revoke_date' : None,
                             'passphrase' : group_passphrase},
                            {'type' : 'group_key',
                             'group_id' : group_name,
                             'owner_id' : user1,
                             'node_name' : test_params.node_name,
                             'use' : 'read',
                             'public_key_hash' : group_pkh},
                            {'type' : 'group_key',
                             'group_id' : group_name,
                             'owner_id' : user1,
                             'node_name' : test_params.node_name,
                             'use' : 'post',
                             'public_key_hash' : group_pkh}]}

invitation_str = json.dumps(invitation)

resp = cl.send_message(user1, session1, test_params.node_name,
                       to_user=user2,
                       to_user_key_hash=None,
                       from_user_key_hash=None,
                       message=invitation_str,
                       passphrase=None)
assert(resp['status'] == 'error')
assert(resp['reason'] == 'encryption forced')


resp = cl.send_message(user1, session1, test_params.node_name,
                       to_user=user2,
                       to_user_key_hash=None,
                       from_user_key_hash=None,
                       message=invitation_str,
                       passphrase=None,
                       force_encryption=False)
assert(resp['status'] == 'ok')
assert(resp['resp']['status'] == 'ok')
invitation_id = resp['message_id']




resp = cl.read_last_message_time(user2, session2, test_params.node_name, pkh2, passphrase2)
assert(resp['status'] == 'ok')
assert(resp['resp']['status'] == 'ok')
new_time = resp['resp']['last_message_time']
assert(new_time != None)
last_message_time2 = new_time


resp = cl.read_message_list(user2, session2, test_params.node_name,
                            to_user_key=None,
                            from_user=None,
                            from_user_key=None,
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
assert(message_header['message_id'] == invitation_id)


resp = cl.read_message(user2, session2, test_params.node_name, invitation_id, pkh2, passphrase2)
assert(resp['status'] == 'ok')
assert(resp['resp']['status'] == 'ok')
assert(resp['resp']['message']['message_id'] == invitation_id)
message = resp['resp']['message']['message']
assert(message == invitation_str)

message_obj = json.loads(message)
assert(message_obj['type'] == 'local_command_sequence')

for command in message_obj['commands']:
    if command['type'] == 'private_key':
        key_type = command['key_type']
        pub_key = command['public_key']
        priv_key = command['private_key']
        revoke_date = command['revoke_date']
        public_key_hash = command['public_key_hash']
        passphrase = command['passphrase']
        assert(passphrase == group_passphrase)

        resp = cl.import_private_key(user2, session2, key_type, pub_key, priv_key, revoke_date)
        assert(resp['status'] == 'ok')
        assert(resp['public_key_hash'] == public_key_hash)

    elif command['type'] == 'group_key':
        group_id = command['group_id']
        owner_id = command['owner_id']
        node_name = command['node_name']
        use = command['use']
        public_key_hash = command['public_key_hash']
        resp = cl.assign_local_group_key(user2, session2, group_id, owner_id, node_name, use, public_key_hash)
        assert(resp['status'] == 'ok')

    else:
        assert(False)

resp = cl.list_public_keys(user1, session1)
assert(resp['status'] == 'ok')

resp = cl.list_private_keys(user1, session1)
assert(resp['status'] == 'ok')

resp = cl.list_user_keys(user1, session1)
assert(resp['status'] == 'ok')

resp = cl.list_group_keys(user1, session1)
assert(resp['status'] == 'ok')

resp = cl.list_other_user_keys(user1, session1)
assert(resp['status'] == 'ok')


resp = cl.list_public_keys(user2, session2)
assert(resp['status'] == 'ok')

resp = cl.list_private_keys(user2, session2)
assert(resp['status'] == 'ok')

resp = cl.list_user_keys(user2, session2)
assert(resp['status'] == 'ok')

resp = cl.list_group_keys(user2, session2)
assert(resp['status'] == 'ok')

resp = cl.list_other_user_keys(user2, session2)
assert(resp['status'] == 'ok')



resp = cl.read_group_quota(user2, session2, test_params.node_name, group_name, user1, group_passphrase)
assert(resp['status'] == 'ok')
assert(resp['resp']['status'] == 'ok')


resp = cl.read_group_quota(user2, session2, test_params.node_name, group_name, user1, group_passphrase)
assert(resp['status'] == 'ok')
assert(resp['resp']['status'] == 'ok')


resp = cl.encrypt(user2, session2, group_pkh, post1)
assert(resp['status'] == 'ok')
cipher = resp['ciphertext']


resp = cl.make_post(user2, session2, test_params.node_name, group_name, user1, cipher, group_passphrase)
assert(resp['status'] == 'ok')
assert(resp['resp']['status'] == 'error')
assert(resp['resp']['reason'] == 'proof of work required')
parameters = resp['resp']['parameters']


resp = cl.set_local_group_access(user2, session2, group_name, user1, test_params.node_name, 'post', 'proof_of_work/' + parameters)
assert(resp['status'] == 'ok')

resp = cl.read_max_post_size(user2, session2, test_params.node_name, group_name, user1, group_passphrase)
assert(resp['status'] == 'ok')
assert(resp['resp']['status'] == 'ok')
assert(resp['resp']['max_post_size'] == None)

resp = cl.change_max_post_size(user1, session1, test_params.node_name, group_name, 1, pkh1, passphrase1)
assert(resp['status'] == 'ok')
assert(resp['resp']['status'] == 'ok')

resp = cl.read_max_post_size(user2, session2, test_params.node_name, group_name, user1, group_passphrase)
assert(resp['status'] == 'ok')
assert(resp['resp']['status'] == 'ok')
assert(resp['resp']['max_post_size'] == 1)

resp = cl.make_post(user2, session2, test_params.node_name, group_name, user1, cipher, group_passphrase)
assert(resp['status'] == 'ok')
assert(resp['resp']['status'] == 'error')
assert(resp['resp']['reason'] == 'post too large')
post1_id = resp['post_id']

resp = cl.change_max_post_size(user1, session1, test_params.node_name, group_name, None, pkh1, passphrase1)
assert(resp['status'] == 'ok')
assert(resp['resp']['status'] == 'ok')

resp = cl.read_max_post_size(user2, session2, test_params.node_name, group_name, user1, group_passphrase)
assert(resp['status'] == 'ok')
assert(resp['resp']['status'] == 'ok')
assert(resp['resp']['max_post_size'] == None)


resp = cl.make_post(user2, session2, test_params.node_name, group_name, user1, cipher, group_passphrase)
assert(resp['status'] == 'ok')
assert(resp['resp']['status'] == 'ok')
post1_id = resp['post_id']


resp = cl.read_last_post_time(user1, session1, test_params.node_name, group_name, user1, group_passphrase)
assert(resp['status'] == 'ok')
assert(resp['resp']['status'] == 'ok')
new_time = resp['resp']['last_post_time']
assert(new_time != None)
last_post_time1 = new_time

resp = cl.read_post_list(user1, session1, test_params.node_name, group_name, user1,
                         start_time=last_post_time1,
                         end_time=None,
                         max_records=None,
                         order=None,
                         passphrase=group_passphrase)
assert(resp['status'] == 'ok')
assert(resp['resp']['status'] == 'ok')
post_list = resp['resp']['post_list']
assert(len(post_list) == 1)
post_header = post_list[0]
assert(post_header['post_id'] == post1_id)


resp = cl.read_post(user1, session1, test_params.node_name, group_name, user1, post1_id, group_passphrase)
assert(resp['status'] == 'ok')
assert(resp['resp']['status'] == 'ok')
assert(resp['resp']['post']['post_id'] == post1_id)
post_cipher = resp['resp']['post']['data']


resp = cl.decrypt(user1, session1, group_pkh, post_cipher, group_passphrase)
assert(resp['status'] == 'ok')
post = resp['plaintext']
assert(post == post1)



resp = cl.make_post(user1, session1, test_params.node_name, group_name, user1, post2, group_passphrase)
assert(resp['status'] == 'ok')
assert(resp['resp']['status'] == 'ok')
post2_id = resp['post_id']



resp = cl.read_last_post_time(user2, session2, test_params.node_name, group_name, user1, group_passphrase)
assert(resp['status'] == 'ok')
assert(resp['resp']['status'] == 'ok')
new_time = resp['resp']['last_post_time']
assert(new_time != None)
old_time = last_post_time2
last_post_time2 = new_time

resp = cl.read_post_list(user1, session1, test_params.node_name, group_name, user1,
                         start_time=None,
                         end_time=None,
                         max_records=None,
                         order='desc',
                         passphrase=group_passphrase)
assert(resp['status'] == 'ok')
assert(resp['resp']['status'] == 'ok')
post_list = resp['resp']['post_list']
assert(len(post_list) == 2)
post_header = post_list[0]

print post_header['post_id'],post2_id

assert(post_header['post_id'] == post2_id)

resp = cl.read_post(user2, session2, test_params.node_name, group_name, user1, post2_id, group_passphrase)
assert(resp['status'] == 'ok')
assert(resp['resp']['status'] == 'ok')
assert(resp['resp']['post']['post_id'] == post2_id)
post = resp['resp']['post']['data']
assert(post == post2)


resp = cl.delete_post(user1, session1, test_params.node_name, group_name, user1, post2_id, passphrase2)
assert(resp['status'] == 'ok')
assert(resp['resp']['status'] == 'ok')


resp = cl.read_post(user2, session2, test_params.node_name, group_name, user1, post2_id, group_passphrase)
assert(resp['status'] == 'ok')
assert(resp['resp']['status'] == 'error')


resp = cl.set_group_access(user1, session1, test_params.node_name, group_name, 'post', 'block', pkh1, passphrase1)
assert(resp['status'] == 'ok')
assert(resp['resp']['status'] == 'ok')


resp = cl.make_post(user2, session2, test_params.node_name, group_name, user1, spam_post, group_passphrase)
assert(resp['status'] == 'ok')
assert(resp['resp']['status'] == 'error')


resp = cl.set_group_access(user1, session1, test_params.node_name, group_name, 'read', 'block', pkh1, passphrase1)
assert(resp['status'] == 'ok')
assert(resp['resp']['status'] == 'ok')

resp = cl.read_post(user2, session2, test_params.node_name, group_name, user1, post1_id, group_passphrase)
assert(resp['status'] == 'ok')
assert(resp['resp']['status'] == 'error')

resp = cl.set_group_access(user1, session1, test_params.node_name, group_name, 'read', 'allow', pkh1, passphrase1)
assert(resp['status'] == 'ok')
assert(resp['resp']['status'] == 'ok')

resp = cl.read_post(user2, session2, test_params.node_name, group_name, user1, post1_id, group_passphrase)
assert(resp['status'] == 'ok')
assert(resp['resp']['status'] == 'ok')


resp = cl.delete_local_group_key(user2, session2, group_name, user1, node_name, 'read')
assert(resp['status'] == 'ok')

resp = cl.read_post(user2, session2, test_params.node_name, group_name, user1, post1_id, group_passphrase)
assert(resp['status'] == 'ok')
assert(resp['resp']['status'] == 'error')

resp = cl.set_group_key(user1, session1, test_params.node_name, group_name, 'read', None, pkh1, passphrase1)
assert(resp['status'] == 'ok')
assert(resp['resp']['status'] == 'ok')

resp = cl.read_post(user2, session2, test_params.node_name, group_name, user1, post1_id, group_passphrase)
assert(resp['status'] == 'ok')
assert(resp['resp']['status'] == 'ok')

resp = cl.set_group_key(user1, session1, test_params.node_name, group_name, 'read', group_pkh, pkh1, passphrase1)
assert(resp['status'] == 'ok')
assert(resp['resp']['status'] == 'ok')

resp = cl.read_post(user2, session2, test_params.node_name, group_name, user1, post1_id, group_passphrase)
assert(resp['status'] == 'ok')
assert(resp['resp']['status'] == 'error')

resp = cl.assign_local_group_key(user2, session2, group_name, user1, node_name, 'read', group_pkh)
assert(resp['status'] == 'ok')

resp = cl.read_post(user2, session2, test_params.node_name, group_name, user1, post1_id, group_passphrase)
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


