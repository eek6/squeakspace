import urllib
import json
import crypt_all
import util as ut
import squeak_ex as ex
import client_raw as raw


class Client:

    def __init__(self, conn, node_name, show_traffic=True):
        self.client_raw = raw.ClientRaw(conn, show_traffic)
        self.node_name = node_name

    #complain

    #group-access

    def change_group_access(self, group_id, owner_id, use, access, auth_key):

        timestamp = ut.current_time()

        request_string = ut.serialize_request(
                ['CHANGE_GROUP_ACCESS', timestamp, self.node_name, group_id, owner_id, use, access])

        signature = auth_key.sign(request_string)

        return self.client_raw.change_group_access(
                timestamp, self.node_name,
                group_id, owner_id, use, access,
                auth_key.public_key_hash, signature)[0]


    def read_group_access(self, group_id, owner_id, use, auth_key):

        timestamp = ut.current_time()
    
        request_string = ut.serialize_request(
                ['READ_GROUP_ACCESS', timestamp, self.node_name, group_id, owner_id, use])

        signature = None
        if auth_key != None:
            signature = auth_key.sign(request_string)

        return self.client_raw.read_group_access(
                timestamp, self.node_name,
                group_id, owner_id, use,
                signature)[0]

    #group-key

    def change_group_key(self, group_id, owner_id, key_use, pub_key, auth_key):

        timestamp = ut.current_time()

        key_type = None
        public_key = None
        if pub_key != None:
            key_type = pub_key.key_type
            public_key = pub_key.public_key
         
        request_string = ut.serialize_request(
                ['CHANGE_GROUP_KEY', timestamp, self.node_name, group_id, owner_id,
                 key_use, key_type, public_key])

        signature = auth_key.sign(request_string)

        return self.client_raw.change_group_key(
                timestamp, self.node_name,
                group_id, owner_id, key_use, key_type, public_key,
                auth_key.public_key_hash, signature)[0]


    def read_group_key(self, group_id, owner_id, key_use, auth_key):

        timestamp = ut.current_time()
    
        request_string = ut.serialize_request(
                ['READ_GROUP_KEY', timestamp, self.node_name, group_id, owner_id, key_use])

        signature = None
        if auth_key != None:
            signature = auth_key.sign(request_string)

        return self.client_raw.read_group_key(
                timestamp, self.node_name,
                group_id, owner_id, key_use,
                auth_key.public_key_hash, signature)[0]

    #group-config
    
    #group
    
    def create_group(self,
                     group_id, owner_id,
                     post_access, read_access, delete_access,
                     posting_pub_key, reading_pub_key, delete_pub_key,
                     quota_allocated, when_space_exhausted, auth_key):
    
        timestamp = ut.current_time()

        posting_key_type = None
        posting_pub_key_str = None
        reading_key_type = None
        reading_pub_key_str = None
        delete_key_type = None
        delete_pub_key_str = None

        if posting_pub_key != None:
            posting_key_type = posting_pub_key.key_type
            posting_pub_key_str = posting_pub_key.public_key

        if reading_pub_key != None:
            reading_key_type = reading_pub_key.key_type
            reading_pub_key_str = reading_pub_key.public_key

        if delete_pub_key != None:
            delete_key_type = delete_pub_key.key_type
            delete_pub_key_str = delete_pub_key.public_key
    
        request_string = ut.serialize_request(
            ['CREATE_GROUP', timestamp, self.node_name,
             group_id, owner_id,
             post_access, read_access, delete_access,
             posting_key_type, posting_pub_key_str,
             reading_key_type, reading_pub_key_str,
             delete_key_type, delete_pub_key_str,
             quota_allocated, when_space_exhausted])

        signature = auth_key.sign(request_string)
    
        #ut.assert_access(read_access)
        #ut.assert_access(post_access)
        #ut.assert_access(delete_access)
        #ut.assert_public_key(posting_key_type, posting_pub_key)
        #ut.assert_public_key(reading_key_type, reading_pub_key)
        #ut.assert_public_key(delete_key_type, delete_pub_key)
        #ut.assert_exhaustion(when_space_exhausted)
    
        return self.client_raw.create_group(
            timestamp, self.node_name, group_id, owner_id,
            post_access, read_access, delete_access,
            posting_key_type, posting_pub_key_str,
            reading_key_type, reading_pub_key_str,
            delete_key_type, delete_pub_key_str,
            quota_allocated, when_space_exhausted,
            auth_key.public_key_hash, signature)[0]
    
    
    def read_group(self, group_id, owner_id, auth_key):
    
        timestamp = ut.current_time()
    
        request_string = ut.serialize_request(
                ['READ_GROUP', timestamp, self.node_name, group_id, owner_id])
    
        signature = auth_key.sign(request_string)
    
        return self.client_raw.read_group(
                timestamp, self.node_name, group_id, owner_id,
                auth_key.public_key_hash, signature)[0]
    
    
    def delete_group(self, group_id, owner_id, auth_key):
    
        timestamp = ut.current_time()
    
        request_string = ut.serialize_request(
                ['DELETE_GROUP', timestamp, self.node_name, group_id, owner_id])
    
        signature = auth_key.sign(request_string)
    
        return self.client_raw.delete_group(
                timestamp, self.node_name, group_id, owner_id,
                auth_key.public_key_hash, signature)[0]
    
    
    #group-quota
    
    def change_group_quota(self, group_id, owner_id, new_size, when_space_exhausted, auth_key):
    
        timestamp = ut.current_time()
    
        request_string = ut.serialize_request(
                ['CHANGE_GROUP_QUOTA', timestamp, self.node_name, group_id, owner_id, new_size, when_space_exhausted])
    
        signature = auth_key.sign(request_string)
    
        return self.client_raw.change_group_quota(
                timestamp, self.node_name, group_id, owner_id, new_size, when_space_exhausted,
                auth_key.public_key_hash, signature)[0]
    
    
    def read_group_quota(self, group_id, owner_id, group_read_key, proof_of_work_args):
        timestamp = ut.current_time()
    
        request_string = ut.serialize_request(
                ['READ_GROUP_QUOTA', timestamp, self.node_name, group_id, owner_id])
    
        read_signature = None
        if group_read_key != None:
            read_signature = group_read_key.sign(request_string)
    
        proof_of_work = None
        if proof_of_work_args != None:
            proof_of_work = make_proof_of_work(proof_of_work_args, request_string)
    
        return self.client_raw.read_group_quota(timestamp, self.node_name, group_id, owner_id, read_signature, proof_of_work)[0]
    
        
    
    #last-message-time
    
    def read_last_message_time(self, user_id, auth_key):
        timestamp = ut.current_time()
    
        request_string = ut.serialize_request(
                ['READ_LAST_MESSAGE_TIME', timestamp, self.node_name, user_id])
    
        signature = None
        if auth_key != None:
            signature = auth_key.sign(request_string)
    
        return self.client_raw.read_last_message_time(timestamp, self.node_name, user_id, auth_key.public_key_hash, signature)[0]
    
    #last-post-time
    
    def read_last_post_time(self, group_id, owner_id, group_read_key, proof_of_work_args):
        timestamp = ut.current_time()
    
        request_string = ut.serialize_request(
                ['READ_LAST_POST_TIME', timestamp, self.node_name, group_id, owner_id])
    
        read_signature = None
        if group_read_key != None:
            read_signature = group_read_key.sign(request_string)
    
        proof_of_work = None
        if proof_of_work_args != None:
            proof_of_work = ut.make_proof_of_work(proof_of_work_args, request_string)
    
        return self.client_raw.read_last_post_time(
                timestamp, self.node_name, group_id, owner_id, read_signature, proof_of_work)[0]
    
    #query-message-access

    def query_message_access(self, to_user, from_user, from_key):

        timestamp = ut.current_time()


        public_key_hash = None
        signature = None
        if from_key != None:
            request_string = ut.serialize_request(
                    ['QUERY_MESSAGE_ACCESS', timestamp, self.node_name, to_user, from_user, from_key.public_key_hash])

            public_key_hash = from_key.public_key_hash
            signature = from_key.sign(request_string)

        return self.client_raw.query_message_access(
                timestamp, self.node_name, to_user, from_user, public_key_hash, signature)[0]
    
    #message-access
    
    def read_message_access(self, user_id, from_user_key_hash, auth_key):
    
        timestamp = ut.current_time()
    
        request_string = ut.serialize_request(
                ['READ_MESSAGE_ACCESS', timestamp, self.node_name, user_id, from_user_key_hash])
    
        signature = auth_key.sign(request_string)
    
        return self.client_raw.read_message_access(
                timestamp, self.node_name, user_id, from_user_key_hash, auth_key.public_key_hash, signature)[0]
    
    
    def set_message_access(self, user_id, from_user_key_hash, access, auth_key):
    
        timestamp = ut.current_time()
    
        request_string = ut.serialize_request(
                ['SET_MESSAGE_ACCESS', timestamp, self.node_name, user_id, from_user_key_hash, access])
    
        signature = auth_key.sign(request_string)
    
        return self.client_raw.set_message_access(
                timestamp, self.node_name, user_id, from_user_key_hash, access, auth_key.public_key_hash, signature)[0]
    
    
    def delete_message_access(self, user_id, from_user_key_hash, auth_key):
    
        timestamp = ut.current_time()
    
        request_string = ut.serialize_request(
                ['DELETE_MESSAGE_ACCESS', timestamp, self.node_name, user_id, from_user_key_hash])
    
        signature = auth_key.sign(request_string)
    
        return self.client_raw.delete_message_access(
                timestamp, self.node_name, user_id, from_user_key_hash, auth_key.public_key_hash, signature)[0]
    
    
    #message-list
    
    
    def read_message_list(self, user_id, start_time, end_time, max_records, order, auth_key):
    
        timestamp = ut.current_time()
    
        request_string = ut.serialize_request(
                ['READ_MESSAGE_LIST',
                 timestamp, self.node_name, user_id,
                 start_time, end_time, max_records, order])
    
        signature = auth_key.sign(request_string)
    
        return self.client_raw.read_message_list(
                timestamp, self.node_name, user_id,
                start_time, end_time, max_records, order,
                auth_key.public_key_hash, signature)[0]
    
    
    #message
    
    def read_message(self, user_id, message_id, auth_key):
    
        timestamp = ut.current_time()
    
        request_string = ut.serialize_request(
                ['READ_MESSAGE', timestamp, self.node_name, user_id, message_id])
    
        signature = auth_key.sign(request_string)
    
        return self.client_raw.read_message(
                timestamp, self.node_name, user_id, message_id,
                auth_key.public_key_hash, signature)[0]


    def send_message(
            self, to_user, to_user_key_hash,
            from_user, from_key,
            message, proof_of_work_args):
    
        timestamp = ut.current_time()
    
        message_hash = ut.hash_function(message)
    
        from_user_key_hash = None
        if from_key != None:
            from_user_key_hash = from_key.public_key_hash
    
        request_string = ut.serialize_request(
                ['SEND_MESSAGE', timestamp, self.node_name,
                 to_user, to_user_key_hash,
                 from_user, from_user_key_hash,
                 message_hash])
    
        message_id = ut.hash_function(request_string)
    
        from_signature = None
        if from_key != None:
            from_signature = from_key.sign(message_id)
    
        proof_of_work = None
        if proof_of_work_args != None:
            proof_of_work = ut.make_proof_of_work(proof_of_work_args, message_id)
    
        resp = self.client_raw.send_message(
                timestamp, self.node_name,
                to_user, to_user_key_hash,
                from_user, from_user_key_hash,
                message_hash,
                message_id, message,
                from_signature, proof_of_work)[0]
    
        return resp, (message_id, timestamp, message_hash, from_signature, proof_of_work)


    
    def delete_message(self, user_id, message_id, auth_key):
    
        timestamp = ut.current_time()
    
        request_string = ut.serialize_request(
                ['DELETE_MESSAGE', timestamp, self.node_name, user_id, message_id])
    
        signature = auth_key.sign(request_string)
    
        return self.client_raw.delete_message(
                timestamp, self.node_name, user_id, message_id,
                auth_key.public_key_hash, signature)[0]
    
    #message-quota
    
    def change_message_quota(self, user_id, new_size, when_space_exhausted, auth_key):
    
        timestamp = ut.current_time()
    
        request_string = ut.serialize_request(
                ['CHANGE_MESSAGE_QUOTA', timestamp, self.node_name, user_id, new_size, when_space_exhausted])
    
        signature = auth_key.sign(request_string)
    
        return self.client_raw.change_message_quota(
                timestamp, self.node_name, user_id, new_size, when_space_exhausted,
                auth_key.public_key_hash, signature)[0]
    
    
    def read_message_quota(self, user_id, auth_key):
    
        timestamp = ut.current_time()
    
        request_string = ut.serialize_request(
                ['READ_MESSAGE_QUOTA', timestamp, self.node_name, user_id])
    
        signature = auth_key.sign(request_string)
    
        return self.client_raw.read_message_quota(timestamp, self.node_name, user_id, auth_key.public_key_hash, signature)[0]
    
    
    #node
    
    #post-list
    
    def read_post_list(self,
                       group_id, owner_id,
                       start_time, end_time, max_records, order,
                       group_read_key, proof_of_work_args):
    
        timestamp = ut.current_time()
    
        request_string = ut.serialize_request(
                ['READ_POST_LIST', timestamp, self.node_name,
                 group_id, owner_id,
                 start_time, end_time, max_records, order])
    
        read_signature = None
        if group_read_key != None:
            read_signature = group_read_key.sign(request_string)
    
        proof_of_work = None
        if proof_of_work_args != None:
            proof_of_work = ut.make_proof_of_work(proof_of_work_args, request_string)
     
        return self.client_raw.read_post_list(
                timestamp, self.node_name, group_id, owner_id,
                start_time, end_time, max_records, order,
                read_signature, proof_of_work)[0]
    
    
    #post
    
    
    def make_post(self, group_id, owner_id, data, post_key, proof_of_work_args):
    
        timestamp = ut.current_time()
    
        data_hash = ut.hash_function(data)
    
        request_string = ut.serialize_request(
                ['MAKE_POST', timestamp, self.node_name, group_id, owner_id, data_hash])
    
        post_id = ut.hash_function(request_string)
    
        post_signature = None
        if post_key != None:
            post_signature = post_key.sign(post_id)
    
        proof_of_work = None
        if proof_of_work_args != None:
            proof_of_work = ut.make_proof_of_work(proof_of_work_args, post_id)
    
        resp = self.client_raw.make_post(
                timestamp, self.node_name, group_id, owner_id,
                data_hash, post_id, data,
                post_signature, proof_of_work)[0]
    
        gen = (post_id, timestamp, data_hash, post_signature, proof_of_work)
    
        return resp, gen
    
    
    def read_post(self, group_id, owner_id, post_id, read_key, proof_of_work_args):
    
        timestamp = ut.current_time()
    
        request_string = ut.serialize_request(
                ['READ_POST', timestamp, self.node_name, group_id, owner_id, post_id])
    
        read_signature = None
        if read_key != None:
            read_signature = read_key.sign(request_string)
    
        proof_of_work = None
        if proof_of_work_args != None:
            proof_of_work = ut.make_proof_of_work(proof_of_work_args, request_string)
    
        return self.client_raw.read_post(
                timestamp, self.node_name,
                group_id, owner_id, post_id,
                read_signature, proof_of_work)[0]
    
    def delete_post(self, group_id, owner_id, post_id, delete_key, proof_of_work_args):
    
        timestamp = ut.current_time()
    
        request_string = ut.serialize_request(
                ['DELETE_POST', timestamp, self.node_name, group_id, owner_id, post_id])
    
        delete_signature = None
        if delete_key != None:
            delete_signature = delete_key.sign(request_string)
    
        proof_of_work = None
        if proof_of_work_args != None:
            proof_of_work = ut.make_proof_of_work(proof_of_work_args, request_string)
    
        return self.client_raw.delete_post(
                timestamp, self.node_name, group_id, owner_id, post_id,
                delete_signature, proof_of_work)[0]
    
    #user
    
    def create_user(self, user_id, pub_key, revoke_date,
                    default_message_access, when_mail_exhausted,
                    quota_size, mail_quota_size,
                    user_class, auth_token):

        return self.client_raw.create_user(
                self.node_name, user_id,
                pub_key.key_type, pub_key.public_key, pub_key.public_key_hash, revoke_date,
                default_message_access, when_mail_exhausted,
                quota_size, mail_quota_size,
                user_class, auth_token)[0]
    
    
    def read_user(self, user_id, auth_key):
    
        timestamp = ut.current_time()
    
        request_string = ut.serialize_request(
                ['READ_USER', timestamp, self.node_name, user_id]) 
    
        signature = auth_key.sign(request_string)
    
        return self.client_raw.read_user(
                timestamp, self.node_name, user_id,
                auth_key.public_key_hash, signature)[0]
    
    
    def delete_user(self, user_id, auth_key):
    
        timestamp = ut.current_time()
    
        request_string = ut.serialize_request(
                ['DELETE_USER', timestamp, self.node_name, user_id])
    
        signature = auth_key.sign(request_string)
    
        return self.client_raw.delete_user(timestamp, self.node_name, user_id, auth_key.public_key_hash, signature)[0]
    
    # user-quota
    
    def change_user_quota(self, user_id, new_size, user_class, auth_token, auth_key):
    
        timestamp = ut.current_time()
    
        request_string = ut.serialize_request(
                ['CHANGE_USER_QUOTA', timestamp, self.node_name, user_id, new_size, user_class, auth_token])
    
        signature = auth_key.sign(request_string)
    
        return self.client_raw.change_user_quota(
                timestamp, self.node_name, user_id, new_size,
                user_class, auth_token,
                auth_key.public_key_hash, signature)[0]
    
    
    
    def read_user_quota(self, user_id, auth_key):
    
        timestamp = ut.current_time()
    
        request_string = ut.serialize_request(
                ['READ_USER_QUOTA', timestamp, self.node_name, user_id])
    
        signature = auth_key.sign(request_string)
    
        return self.client_raw.read_user_quota(timestamp, self.node_name, user_id, auth_key.public_key_hash, signature)[0]
    
    
    
    # version
    
    
    def read_version(self):
    
        return self.client_raw.read_version(self.node_name)[0]
    
    
    
    # database
    
    def send_debug(self, query):
    
        return self.client_raw.send_debug(query)[0]
         
    
    def assert_db_empty(self):
    
        resp = self.send_debug({'action' : 'database'})
        assert(resp['status'] == 'ok')
        database = resp['res']
    
        assert(len(database['users']) == 0)
        assert(len(database['users']) == 0)
        assert(len(database['keys']) == 0)
        assert(len(database['storage_quotas']) == 1) # 1 root quota.
        assert(len(database['connections']) == 0)
        assert(len(database['groups']) == 0)
        assert(len(database['complaints']) == 0)
        assert(len(database['priv_keys']) == 0)
        assert(len(database['certificates']) == 0)
        assert(len(database['messages']) == 0)
        assert(len(database['enc_priv_keys']) == 0)
        assert(len(database['group_posts']) == 0)
        assert(len(database['hosts']) == 0)
        assert(len(database['message_access']) == 0)
        assert(len(database['storage_reports']) == 0)
    
    
    def assert_integrity(self, all_local=True):
    
        resp = self.send_debug({'action' : 'integrity', 'all_local' : all_local})
        assert(resp['status'] == 'ok')
        errors = resp['res']
    
        assert(len(errors) == 0)
    
