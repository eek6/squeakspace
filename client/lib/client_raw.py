import urllib
import json

show_traffic = True

def send_and_get(conn, method, url, body=None):
    #headers = {'Accept' : 'application/json'}
    headers = {}
    if body != None:
        headers['Content-Type'] = 'application/x-www-form-urlencoded'
    if show_traffic:
        print 'Send:'
        print method
        print url
        print body

    conn.connect()
    conn.request(method, url, body, headers)
    resp = conn.getresponse()
    body = resp.read()
    conn.close()

    if show_traffic:
        print 'Recv:', resp.status, resp.reason
        print body

    return json.loads(body)

def blank_nones(obj):
    for key in obj.keys():
        if obj[key] == None:
            obj[key] = ''
    return obj

def encode(obj):
    return urllib.urlencode(blank_nones(obj))

#complain

#group-config

#group

def create_group(
        conn,
        timestamp, node_name, group_id, owner_id,
        read_access, post_access, delete_access,
        posting_key_type, posting_pub_key,
        reading_key_type, reading_pub_key,
        delete_key_type, delete_pub_key,
        quota_allocated, when_space_exhausted,
        public_key_hash, signature):

    method = 'POST'
    url = '/group'
    body = encode(
            {'timestamp' : timestamp,
             'node_name' : node_name,
             'group_id' : group_id,
             'owner_id' : owner_id,
             'read_access' : read_access,
             'post_access' : post_access,
             'delete_access' : delete_access,
             'posting_key_type' : posting_key_type,
             'posting_pub_key' : posting_pub_key,
             'reading_key_type' : reading_key_type,
             'reading_pub_key' : reading_pub_key,
             'delete_key_type' : delete_key_type,
             'delete_pub_key' : delete_pub_key,
             'quota_allocated' : quota_allocated,
             'when_space_exhausted' : when_space_exhausted,
             'public_key_hash' : public_key_hash,
             'signature' : signature})

    return send_and_get(conn, method, url, body)

def read_group(conn, timestamp, node_name, group_id, owner_id, public_key_hash, signature):

    method = 'GET'
    url = '/group?' + encode(
            {'timestamp' : timestamp,
             'node_name' : node_name,
             'group_id' : group_id,
             'owner_id' : owner_id,
             'public_key_hash' : public_key_hash,
             'signature' : signature})

    return send_and_get(conn, method, url, body)


def delete_group(conn, timestamp, node_name, group_id, owner_id,
                      public_key_hash, signature):

    method = 'DELETE'
    url = '/group'
    body = encode(
            {'timestamp' : timestamp,
             'node_name' : node_name,
             'group_id' : group_id,
             'owner_id' : owner_id,
             'public_key_hash' : public_key_hash,
             'signature' : signature})

    return send_and_get(conn, method, url, body)

#group-quota

def change_group_quota(conn,
        timestamp, node_name, group_id, owner_id, new_size, when_space_exhausted,
        public_key_hash, signature):

    method = 'POST'
    url = '/group-quota'
    body = encode(
            {'timestamp' : timestamp,
             'node_name' : node_name,
             'group_id' : group_id,
             'owner_id' : owner_id,
             'new_size' : new_size,
             'when_space_exhausted' : when_space_exhausted,
             'public_key_hash' : public_key_hash,
             'signature' : signature})

    return send_and_get(conn, method, url, body)

def read_group_quota(conn,
        timestamp, node_name, group_id, owner_id,
        read_signature, proof_of_work):

    method = 'GET'
    url = '/group-quota?' + encode(
            {'timestamp' : timestamp,
             'node_name' : node_name,
             'group_id' : group_id,
             'owner_id' : owner_id,
             'read_signature' : read_signature,
             'proof_of_work' : proof_of_work})

    return send_and_get(conn, method, url)


#last_message_time

def read_last_message_time(conn, timestamp, node_name, user_id, public_key_hash, signature):

    method = 'GET'
    url = '/last-message-time?' + encode(
            {'timestamp' : timestamp,
             'node_name' : node_name,
             'user_id' : user_id,
             'public_key_hash' : public_key_hash,
             'signature' : signature})

    return send_and_get(conn, method, url)


#last_post_time

def read_last_post_time(conn, timestamp, node_name, group_id, owner_id, read_signature, proof_of_work):

    method = 'GET'
    url = '/last-post-time?' + encode(
            {'timestamp' : timestamp,
             'node_name' : node_name,
             'group_id' : group_id,
             'owner_id' : owner_id,
             'read_signature' : read_signature,
             'proof_of_work' : proof_of_work})

    return send_and_get(conn, method, url)


#message-access


def read_message_access(conn,
        timestamp, node_name, user_id, from_key_hash, public_key_hash, signature):

    method = 'GET'
    url = '/message-access?' + encode(
            {'timestamp' : timestamp,
             'node_name' : node_name,
             'user_id' : user_id,
             'from_key_hash' : from_key_hash,
             'public_key_hash' : public_key_hash,
             'signature' : signature})

    return send_and_get(conn, method, url)

def set_message_access(conn,
        timestamp, node_name, user_id, from_key_hash, access, public_key_hash, signature):

    method = 'POST'
    url = '/message-access'
    body = encode(
            {'timestamp' : timestamp,
             'node_name' : node_name,
             'user_id' : user_id,
             'from_key_hash' : from_key_hash,
             'access' : access,
             'public_key_hash' : public_key_hash,
             'signature' : signature})

    return send_and_get(conn, method, url, body)

def delete_message_access(conn,
        timestamp, node_name, user_id, from_key_hash, public_key_hash, signature):

    method = 'DELETE'
    url = '/message-access'
    body = encode(
            {'timestamp' : timestamp,
             'node_name' : node_name,
             'user_id' : user_id,
             'from_key_hash' : from_key_hash,
             'public_key_hash' : public_key_hash,
             'signature' : signature})

    return send_and_get(conn, method, url, body)





#message-list


def read_message_list(conn, timestamp, node_name, user_id,
                      start_time, end_time, max_records, order,
                      public_key_hash, signature):

    method = 'GET'
    url = '/message-list?' + encode(
            {'timestamp' : timestamp,
             'node_name' : node_name,
             'user_id' : user_id,
             'start_time' : start_time,
             'end_time' : end_time,
             'max_records' : max_records,
             'order' : order,
             'public_key_hash' : public_key_hash,
             'signature' : signature})

    return send_and_get(conn, method, url)


#message

def read_message(conn, timestamp, node_name, user_id, message_id, public_key_hash, signature):

    method = 'GET'
    url = '/message?' + encode(
            {'timestamp' : timestamp,
             'node_name' : node_name,
             'user_id' : user_id,
             'message_id' : message_id,
             'public_key_hash' : public_key_hash,
             'signature' : signature})

    return send_and_get(conn, method, url)

def send_message(conn,
                 timestamp,
                 node_name, to_user, to_user_key_hash,
                 from_user, from_user_key_hash,
                 message_hash,
                 message_id, message,
                 from_signature, proof_of_work):

    method = 'POST'
    url = '/message'
    body = encode(
            {'timestamp' : timestamp,
             'node_name' : node_name,
             'to_user' : to_user,
             'to_user_key_hash' : to_user_key_hash,
             'from_user' : from_user,
             'from_user_key_hash' : from_user_key_hash,
             'message_hash' : message_hash,
             'message_id' : message_id,
             'message' : message,
             'from_signature' : from_signature,
             'proof_of_work' : proof_of_work})

    return send_and_get(conn, method, url, body)


def delete_message(conn, timestamp, node_name, user_id, message_id, public_key_hash, signature):

    method = 'DELETE'
    url = '/message'
    body = encode(
            {'timestamp' : timestamp,
             'node_name' : node_name,
             'user_id' : user_id,
             'message_id' : message_id,
             'public_key_hash' : public_key_hash,
             'signature' : signature})

    return send_and_get(conn, method, url, body)


#message-quota

def change_message_quota(conn,
        timestamp, node_name, user_id, new_size, when_space_exhausted,
        public_key_hash, signature):

    method = 'POST'
    url = '/message-quota'
    body = encode(
            {'timestamp' : timestamp,
             'node_name' : node_name,
             'user_id' : user_id,
             'new_size' : new_size,
             'when_space_exhausted' : when_space_exhausted,
             'public_key_hash' : public_key_hash,
             'signature' : signature})

    return send_and_get(conn, method, url, body)


def read_message_quota(conn,
        timestamp, node_name, user_id, public_key_hash, signature):

    method = 'GET'
    url = '/message-quota?' + encode(
            {'timestamp' : timestamp,
             'node_name' : node_name,
             'user_id' : user_id,
             'public_key_hash' : public_key_hash,
             'signature' : signature})

    return send_and_get(conn, method, url)


#node

#post-list


def read_post_list(conn, timestamp, node_name, group_id, owner_id,
                   start_time, end_time, max_records, order,
                   read_signature, proof_of_work):

    method = 'GET'
    url = '/post-list?' + encode(
            {'timestamp' : timestamp,
             'node_name' : node_name,
             'group_id' : group_id,
             'owner_id' : owner_id,
             'start_time' : start_time,
             'end_time' : end_time,
             'max_records' : max_records,
             'order' : order,
             'read_signature' : read_signature,
             'proof_of_work' : proof_of_work})

    return send_and_get(conn, method, url)



#post


def make_post(conn, timestamp, node_name, group_id, owner_id,
              data_hash, post_id, data,
              post_signature, proof_of_work):

    method = 'POST'
    url = '/post'
    body = encode(
            {'timestamp' : timestamp,
             'node_name' : node_name,
             'group_id' : group_id,
             'owner_id' : owner_id,
             'data_hash' : data_hash,
             'post_id' : post_id,
             'data' : data,
             'post_signature' : post_signature,
             'proof_of_work' : proof_of_work})

    return send_and_get(conn, method, url, body)


def read_post(conn, timestamp, node_name, group_id, owner_id, post_id, read_signature, proof_of_work):

    method = 'GET'
    url = '/post?' + encode(
            {'timestamp' : timestamp,
             'node_name' : node_name,
             'group_id' : group_id,
             'owner_id' : owner_id,
             'post_id' : post_id,
             'read_signature' : read_signature,
             'proof_of_work' : proof_of_work})

    return send_and_get(conn, method, url)



def delete_post(conn, timestamp, node_name, group_id, owner_id, post_id, delete_signature, proof_of_work):

    method = 'DELETE'
    url = '/post'
    body = encode(
            {'timestamp' : timestamp,
             'node_name' : node_name,
             'group_id' : group_id,
             'owner_id' : owner_id,
             'post_id' : post_id,
             'delete_signature' : delete_signature,
             'proof_of_work' : proof_of_work})

    return send_and_get(conn, method, url, body)



#user

def create_user(conn, user_id,
                key_type, public_key, public_key_hash, revoke_date,
                default_message_access, when_mail_exhausted,
                quota_size, mail_quota_size,
                user_class, auth_token):

    method = 'POST'
    url = '/user'
    body = encode(
            {'user_id' : user_id,
             'key_type' : key_type,
             'public_key' : public_key,
             'public_key_hash' : public_key_hash,
             'revoke_date' : revoke_date,
             'default_message_access' : default_message_access,
             'when_mail_exhausted' : when_mail_exhausted,
             'quota_size' : quota_size,
             'mail_quota_size' : mail_quota_size,
             'user_class' : user_class,
             'auth_token' : auth_token})

    return send_and_get(conn, method, url, body)


def read_user(conn, timestamp, node_name, user_id, public_key_hash, signature):

    method = 'GET'
    url = '/user?' + encode(
            {'timestamp' : timestamp,
             'node_name' : node_name,
             'user_id' : user_id,
             'public_key_hash' : public_key_hash,
             'signature' : signature})

    return send_and_get(conn, method, url)


def delete_user(conn, timestamp, node_name, user_id, public_key_hash, signature):

    method = 'DELETE'
    url = '/user'
    body = encode(
            {'timestamp' : timestamp,
             'node_name' : node_name,
             'user_id' : user_id,
             'public_key_hash' : public_key_hash,
             'signature' : signature})

    return send_and_get(conn, method, url, body)


#user-quota

def change_user_quota(conn,
        timestamp, node_name, user_id, new_size, user_class, auth_token,
        public_key_hash, signature):

    method = 'POST'
    url = '/user-quota'
    body = encode(
            {'timestamp' : timestamp,
             'node_name' : node_name,
             'user_id' : user_id,
             'new_size' : new_size,
             'user_class' : user_class,
             'auth_token' : auth_token,
             'public_key_hash' : public_key_hash,
             'signature' : signature})

    return send_and_get(conn, method, url, body)


def read_user_quota(conn, timestamp, node_name, user_id, public_key_hash, signature):

    method = 'GET'
    url = '/user-quota?' + encode(
            {'timestamp' : timestamp,
             'node_name' : node_name,
             'user_id' : user_id,
             'public_key_hash' : public_key_hash,
             'signature' : signature})
    
    return send_and_get(conn, method, url)


def read_version(conn):

    method = 'GET'
    url = '/version'

    return send_and_get(conn, method, url)


def send_debug(conn, query):

    method = 'GET'
    url = '/debug?' + encode(query)

    return send_and_get(conn, method, url)
