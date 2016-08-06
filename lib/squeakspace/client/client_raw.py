import squeakspace.common.util_client as uc

#show_traffic = True
#
#def send_and_get(conn, method, url, body=None):
#    #headers = {'Accept' : 'application/json'}
#    headers = {}
#    if body != None:
#        headers['Content-Type'] = 'application/x-www-form-urlencoded'
#    if show_traffic:
#        print 'Send:'
#        print method
#        print url
#        print body
#
#    conn.connect()
#    conn.request(method, url, body, headers)
#    resp = conn.getresponse()
#    body = resp.read()
#    conn.close()
#
#    if show_traffic:
#        print 'Recv:', resp.status, resp.reason
#        print body
#
#    return json.loads(body)
#
#def blank_nones(obj):
#    for key in obj.keys():
#        if obj[key] == None:
#            obj[key] = ''
#    return obj
#
#def encode(obj):
#    return urllib.urlencode(blank_nones(obj))
#


class ClientRaw:

    def __init__(self, conn, show_traffic=True):
        self.conn = conn
        self.send_and_getter = uc.SendAndGetter(show_traffic)

    
    #complain
    
    #group-access
    
    def change_group_access(self, timestamp, node_name, group_id, owner_id, use, access, public_key_hash, signature):
    
        method = 'POST'
        url = '/group-access'
        body = uc.encode(
                {'timestamp' : timestamp,
                 'node_name' : node_name,
                 'group_id' : group_id,
                 'owner_id' : owner_id,
                 'use' : use,
                 'access' : access,
                 'public_key_hash' : public_key_hash,
                 'signature' : signature})
    
        return self.send_and_getter.send_and_get(self.conn, method, url, body)
    
    
    def read_group_access(self, timestamp, node_name, group_id, owner_id, use, signature):
    
        method = 'GET'
        url = '/group-access?' + uc.encode(
                {'timestamp' : timestamp,
                 'node_name' : node_name,
                 'group_id' : group_id,
                 'owner_id' : owner_id,
                 'use' : use,
                 'signature' : signature})
    
        return self.send_and_getter.send_and_get(self.conn, method, url)
     
    #group-config

    #group-key

    def change_group_key(self, timestamp, node_name, group_id, owner_id, key_use, key_type, pub_key,
                         public_key_hash, signature):

        method = 'POST'
        url = '/group-key'
        body = uc.encode(
                {'timestamp' : timestamp,
                 'node_name' : node_name,
                 'group_id' : group_id,
                 'owner_id' : owner_id,
                 'key_use' : key_use,
                 'key_type' : key_type,
                 'pub_key' : pub_key,
                 'public_key_hash' : public_key_hash,
                 'signature' : signature})

        return self.send_and_getter.send_and_get(self.conn, method, url, body)

    def read_group_key(self, timestamp, node_name, group_id, owner_id, key_use, public_key_hash, signature):
    
        method = 'GET'
        url = '/group-key?' + uc.encode(
                {'timestamp' : timestamp,
                 'node_name' : node_name,
                 'group_id' : group_id,
                 'owner_id' : owner_id,
                 'key_use' : key_use,
                 'public_key_hash' : public_key_hash,
                 'signature' : signature})
    
        return self.send_and_getter.send_and_get(self.conn, method, url)
 
    #group
    
    def create_group(
            self,
            timestamp, node_name, group_id, owner_id,
            post_access, read_access, delete_access,
            posting_key_type, posting_pub_key,
            reading_key_type, reading_pub_key,
            delete_key_type, delete_pub_key,
            quota_allocated, when_space_exhausted,
            max_post_size,
            public_key_hash, signature):
    
        method = 'POST'
        url = '/group'
        body = uc.encode(
                {'timestamp' : timestamp,
                 'node_name' : node_name,
                 'group_id' : group_id,
                 'owner_id' : owner_id,
                 'post_access' : post_access,
                 'read_access' : read_access,
                 'delete_access' : delete_access,
                 'posting_key_type' : posting_key_type,
                 'posting_pub_key' : posting_pub_key,
                 'reading_key_type' : reading_key_type,
                 'reading_pub_key' : reading_pub_key,
                 'delete_key_type' : delete_key_type,
                 'delete_pub_key' : delete_pub_key,
                 'quota_allocated' : quota_allocated,
                 'when_space_exhausted' : when_space_exhausted,
                 'max_post_size' : max_post_size,
                 'public_key_hash' : public_key_hash,
                 'signature' : signature})
    
        return self.send_and_getter.send_and_get(self.conn, method, url, body)
    
    def read_group(self, timestamp, node_name, group_id, owner_id, public_key_hash, signature):
    
        method = 'GET'
        url = '/group?' + uc.encode(
                {'timestamp' : timestamp,
                 'node_name' : node_name,
                 'group_id' : group_id,
                 'owner_id' : owner_id,
                 'public_key_hash' : public_key_hash,
                 'signature' : signature})
    
        return self.send_and_getter.send_and_get(self.conn, method, url)
    
    
    def delete_group(self, timestamp, node_name, group_id, owner_id,
                          public_key_hash, signature):
    
        method = 'DELETE'
        url = '/group'
        body = uc.encode(
                {'timestamp' : timestamp,
                 'node_name' : node_name,
                 'group_id' : group_id,
                 'owner_id' : owner_id,
                 'public_key_hash' : public_key_hash,
                 'signature' : signature})
    
        return self.send_and_getter.send_and_get(self.conn, method, url, body)
    
    #group-quota
    
    def change_group_quota(self,
            timestamp, node_name, group_id, owner_id, new_size, when_space_exhausted,
            public_key_hash, signature):
    
        method = 'POST'
        url = '/group-quota'
        body = uc.encode(
                {'timestamp' : timestamp,
                 'node_name' : node_name,
                 'group_id' : group_id,
                 'owner_id' : owner_id,
                 'new_size' : new_size,
                 'when_space_exhausted' : when_space_exhausted,
                 'public_key_hash' : public_key_hash,
                 'signature' : signature})
    
        return self.send_and_getter.send_and_get(self.conn, method, url, body)
    
    def read_group_quota(self,
            timestamp, node_name, group_id, owner_id,
            read_signature, proof_of_work):
    
        method = 'GET'
        url = '/group-quota?' + uc.encode(
                {'timestamp' : timestamp,
                 'node_name' : node_name,
                 'group_id' : group_id,
                 'owner_id' : owner_id,
                 'read_signature' : read_signature,
                 'proof_of_work' : proof_of_work})
    
        return self.send_and_getter.send_and_get(self.conn, method, url)
    
    
    #last_message_time
    
    def read_last_message_time(self, timestamp, node_name, user_id, public_key_hash, signature):
    
        method = 'GET'
        url = '/last-message-time?' + uc.encode(
                {'timestamp' : timestamp,
                 'node_name' : node_name,
                 'user_id' : user_id,
                 'public_key_hash' : public_key_hash,
                 'signature' : signature})
    
        return self.send_and_getter.send_and_get(self.conn, method, url)
    
    
    #last_post_time
    
    def read_last_post_time(self, timestamp, node_name, group_id, owner_id, read_signature, proof_of_work):
    
        method = 'GET'
        url = '/last-post-time?' + uc.encode(
                {'timestamp' : timestamp,
                 'node_name' : node_name,
                 'group_id' : group_id,
                 'owner_id' : owner_id,
                 'read_signature' : read_signature,
                 'proof_of_work' : proof_of_work})
    
        return self.send_and_getter.send_and_get(self.conn, method, url)
    
    
    #query-message-access
    
    def query_message_access(self, timestamp, node_name, to_user, from_user, from_user_key_hash, from_user_key_sig):
    
        method = 'GET'
        url = '/query-message-access?' + uc.encode(
                {'timestamp' : timestamp,
                 'node_name' : node_name,
                 'to_user' : to_user,
                 'from_user' : from_user,
                 'from_user_key_hash' : from_user_key_hash,
                 'from_user_key_sig' : from_user_key_sig})
    
        return self.send_and_getter.send_and_get(self.conn, method, url)

    #max-message-size

    def read_max_message_size(self, timestamp, node_name, to_user, from_user, from_user_key_hash, from_user_key_sig):
    
        method = 'GET'
        url = '/max-message-size?' + uc.encode(
                {'timestamp' : timestamp,
                 'node_name' : node_name,
                 'to_user' : to_user,
                 'from_user' : from_user,
                 'from_user_key_hash' : from_user_key_hash,
                 'from_user_key_sig' : from_user_key_sig})
    
        return self.send_and_getter.send_and_get(self.conn, method, url)

    def change_max_message_size(self,
            timestamp, node_name, user_id, new_size,
            public_key_hash, signature):
    
        method = 'POST'
        url = '/max-message-size'
        body = uc.encode(
                {'timestamp' : timestamp,
                 'node_name' : node_name,
                 'user_id' : user_id,
                 'new_size' : new_size,
                 'public_key_hash' : public_key_hash,
                 'signature' : signature})
    
        return self.send_and_getter.send_and_get(self.conn, method, url, body)
 

    #max-post-size

    def read_max_post_size(self, timestamp, node_name, group_id, owner_id, post_signature):
        method = 'GET'
        url = '/max-post-size?' + uc.encode(
                {'timestamp' : timestamp,
                 'node_name' : node_name,
                 'group_id' : group_id,
                 'owner_id' : owner_id,
                 'post_signature' : post_signature})
    
        return self.send_and_getter.send_and_get(self.conn, method, url)


    def change_max_post_size(self,
            timestamp, node_name, group_id, owner_id, new_size,
            public_key_hash, signature):
    
        method = 'POST'
        url = '/max-post-size'
        body = uc.encode(
                {'timestamp' : timestamp,
                 'node_name' : node_name,
                 'group_id' : group_id,
                 'owner_id' : owner_id,
                 'new_size' : new_size,
                 'public_key_hash' : public_key_hash,
                 'signature' : signature})
    
        return self.send_and_getter.send_and_get(self.conn, method, url, body)
 
    
    #message-access
    
    def read_message_access(self,
            timestamp, node_name, user_id, from_user_key_hash, public_key_hash, signature):
    
        method = 'GET'
        url = '/message-access?' + uc.encode(
                {'timestamp' : timestamp,
                 'node_name' : node_name,
                 'user_id' : user_id,
                 'from_user_key_hash' : from_user_key_hash,
                 'public_key_hash' : public_key_hash,
                 'signature' : signature})
    
        return self.send_and_getter.send_and_get(self.conn, method, url)
    
    def set_message_access(self,
            timestamp, node_name, user_id, from_user_key_hash, access, public_key_hash, signature):
    
        method = 'POST'
        url = '/message-access'
        body = uc.encode(
                {'timestamp' : timestamp,
                 'node_name' : node_name,
                 'user_id' : user_id,
                 'from_user_key_hash' : from_user_key_hash,
                 'access' : access,
                 'public_key_hash' : public_key_hash,
                 'signature' : signature})
    
        return self.send_and_getter.send_and_get(self.conn, method, url, body)
    
    def delete_message_access(self,
            timestamp, node_name, user_id, from_user_key_hash, public_key_hash, signature):
    
        method = 'DELETE'
        url = '/message-access'
        body = uc.encode(
                {'timestamp' : timestamp,
                 'node_name' : node_name,
                 'user_id' : user_id,
                 'from_user_key_hash' : from_user_key_hash,
                 'public_key_hash' : public_key_hash,
                 'signature' : signature})
    
        return self.send_and_getter.send_and_get(self.conn, method, url, body)
    
    
    
    
    
    #message-list
    
    
    def read_message_list(self, timestamp, node_name, user_id,
                          to_user_key, from_user, from_user_key,
                          start_time, end_time, max_records, order,
                          public_key_hash, signature):
    
        method = 'GET'
        url = '/message-list?' + uc.encode(
                {'timestamp' : timestamp,
                 'node_name' : node_name,
                 'user_id' : user_id,
                 'to_user_key' : to_user_key,
                 'from_user' : from_user,
                 'from_user_key' : from_user_key,
                 'start_time' : start_time,
                 'end_time' : end_time,
                 'max_records' : max_records,
                 'order' : order,
                 'public_key_hash' : public_key_hash,
                 'signature' : signature})
    
        return self.send_and_getter.send_and_get(self.conn, method, url)
    
    
    #message
    
    def read_message(self, timestamp, node_name, user_id, message_id, public_key_hash, signature):
    
        method = 'GET'
        url = '/message?' + uc.encode(
                {'timestamp' : timestamp,
                 'node_name' : node_name,
                 'user_id' : user_id,
                 'message_id' : message_id,
                 'public_key_hash' : public_key_hash,
                 'signature' : signature})
    
        return self.send_and_getter.send_and_get(self.conn, method, url)
    
    def send_message(self,
                     timestamp,
                     node_name, to_user, to_user_key_hash,
                     from_user, from_user_key_hash,
                     message_hash,
                     message_id, message,
                     from_signature, proof_of_work):
    
        method = 'POST'
        url = '/message'
        body = uc.encode(
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
    
        return self.send_and_getter.send_and_get(self.conn, method, url, body)
    
    
    def delete_message(self, timestamp, node_name, user_id, message_id, public_key_hash, signature):
    
        method = 'DELETE'
        url = '/message'
        body = uc.encode(
                {'timestamp' : timestamp,
                 'node_name' : node_name,
                 'user_id' : user_id,
                 'message_id' : message_id,
                 'public_key_hash' : public_key_hash,
                 'signature' : signature})
    
        return self.send_and_getter.send_and_get(self.conn, method, url, body)
    
    
    #message-quota
    
    def change_message_quota(self,
            timestamp, node_name, user_id, new_size, when_space_exhausted,
            public_key_hash, signature):
    
        method = 'POST'
        url = '/message-quota'
        body = uc.encode(
                {'timestamp' : timestamp,
                 'node_name' : node_name,
                 'user_id' : user_id,
                 'new_size' : new_size,
                 'when_space_exhausted' : when_space_exhausted,
                 'public_key_hash' : public_key_hash,
                 'signature' : signature})
    
        return self.send_and_getter.send_and_get(self.conn, method, url, body)
    
    
    def read_message_quota(self,
            timestamp, node_name, user_id, public_key_hash, signature):
    
        method = 'GET'
        url = '/message-quota?' + uc.encode(
                {'timestamp' : timestamp,
                 'node_name' : node_name,
                 'user_id' : user_id,
                 'public_key_hash' : public_key_hash,
                 'signature' : signature})
    
        return self.send_and_getter.send_and_get(self.conn, method, url)
    
    
    #node
    
    #post-list
    
    
    def read_post_list(self, timestamp, node_name, group_id, owner_id,
                       start_time, end_time, max_records, order,
                       read_signature, proof_of_work):
    
        method = 'GET'
        url = '/post-list?' + uc.encode(
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
    
        return self.send_and_getter.send_and_get(self.conn, method, url)
    
    
    
    #post
    
    
    def make_post(self, timestamp, node_name, group_id, owner_id,
                  data_hash, post_id, data,
                  post_signature, proof_of_work):
    
        method = 'POST'
        url = '/post'
        body = uc.encode(
                {'timestamp' : timestamp,
                 'node_name' : node_name,
                 'group_id' : group_id,
                 'owner_id' : owner_id,
                 'data_hash' : data_hash,
                 'post_id' : post_id,
                 'data' : data,
                 'post_signature' : post_signature,
                 'proof_of_work' : proof_of_work})
    
        return self.send_and_getter.send_and_get(self.conn, method, url, body)
    
    
    def read_post(self, timestamp, node_name, group_id, owner_id, post_id, read_signature, proof_of_work):
    
        method = 'GET'
        url = '/post?' + uc.encode(
                {'timestamp' : timestamp,
                 'node_name' : node_name,
                 'group_id' : group_id,
                 'owner_id' : owner_id,
                 'post_id' : post_id,
                 'read_signature' : read_signature,
                 'proof_of_work' : proof_of_work})
    
        return self.send_and_getter.send_and_get(self.conn, method, url)
    
    
    
    def delete_post(self, timestamp, node_name, group_id, owner_id, post_id, delete_signature, proof_of_work):
    
        method = 'DELETE'
        url = '/post'
        body = uc.encode(
                {'timestamp' : timestamp,
                 'node_name' : node_name,
                 'group_id' : group_id,
                 'owner_id' : owner_id,
                 'post_id' : post_id,
                 'delete_signature' : delete_signature,
                 'proof_of_work' : proof_of_work})
    
        return self.send_and_getter.send_and_get(self.conn, method, url, body)
    
    
    #query-user

    def query_user(self, node_name, user_id):

        method = 'GET'
        url = '/query-user?' + uc.encode(
                {'node_name' : node_name,
                 'user_id' : user_id})
    
        return self.send_and_getter.send_and_get(self.conn, method, url)

    
    #user
    
    def create_user(self, node_name, user_id,
                    key_type, public_key, public_key_hash, revoke_date,
                    default_message_access, when_mail_exhausted,
                    quota_size, mail_quota_size,
                    max_message_size,
                    user_class, auth_token):
    
        method = 'POST'
        url = '/user'
        body = uc.encode(
                {'node_name' : node_name,
                 'user_id' : user_id,
                 'key_type' : key_type,
                 'public_key' : public_key,
                 'public_key_hash' : public_key_hash,
                 'revoke_date' : revoke_date,
                 'default_message_access' : default_message_access,
                 'when_mail_exhausted' : when_mail_exhausted,
                 'quota_size' : quota_size,
                 'mail_quota_size' : mail_quota_size,
                 'max_message_size' : max_message_size,
                 'user_class' : user_class,
                 'auth_token' : auth_token})
    
        return self.send_and_getter.send_and_get(self.conn, method, url, body)
    
    
    def read_user(self, timestamp, node_name, user_id, public_key_hash, signature):
    
        method = 'GET'
        url = '/user?' + uc.encode(
                {'timestamp' : timestamp,
                 'node_name' : node_name,
                 'user_id' : user_id,
                 'public_key_hash' : public_key_hash,
                 'signature' : signature})
    
        return self.send_and_getter.send_and_get(self.conn, method, url)
    
    
    def delete_user(self, timestamp, node_name, user_id, public_key_hash, signature):
    
        method = 'DELETE'
        url = '/user'
        body = uc.encode(
                {'timestamp' : timestamp,
                 'node_name' : node_name,
                 'user_id' : user_id,
                 'public_key_hash' : public_key_hash,
                 'signature' : signature})
    
        return self.send_and_getter.send_and_get(self.conn, method, url, body)
    
    
    #user-quota
    
    def change_user_quota(self,
            timestamp, node_name, user_id, new_size, user_class, auth_token,
            public_key_hash, signature):
    
        method = 'POST'
        url = '/user-quota'
        body = uc.encode(
                {'timestamp' : timestamp,
                 'node_name' : node_name,
                 'user_id' : user_id,
                 'new_size' : new_size,
                 'user_class' : user_class,
                 'auth_token' : auth_token,
                 'public_key_hash' : public_key_hash,
                 'signature' : signature})
    
        return self.send_and_getter.send_and_get(self.conn, method, url, body)
    
    
    def read_user_quota(self, timestamp, node_name, user_id, public_key_hash, signature):
    
        method = 'GET'
        url = '/user-quota?' + uc.encode(
                {'timestamp' : timestamp,
                 'node_name' : node_name,
                 'user_id' : user_id,
                 'public_key_hash' : public_key_hash,
                 'signature' : signature})
        
        return self.send_and_getter.send_and_get(self.conn, method, url)
    
    
    def read_quota_available(self, node_name, user_class):
    
        method = 'GET'
        url = '/quota-available?' + uc.encode(
                {'node_name' : node_name,
                 'user_class' : user_class})
    
        return self.send_and_getter.send_and_get(self.conn, method, url)
 

    def read_version(self, node_name):
    
        method = 'GET'
        url = '/version?' + uc.encode(
                {'node_name' : node_name})
    
        return self.send_and_getter.send_and_get(self.conn, method, url)
    
    
    def send_debug(self, query):
    
        method = 'GET'
        url = '/debug?' + uc.encode(query)
    
        return self.send_and_getter.send_and_get(self.conn, method, url)
