import urllib
import json
import crypt_all
import util as ut
import squeak_ex as ex
import client_raw as raw


class Client:

    def __init__(self, conn, node_name):
        self.conn = conn
        self.node_name = node_name


    #complain
    
    #group-config
    
    #group
    
    def create_group(self,
                     group_id, owner_id,
                     read_access, post_access, delete_access,
                     posting_pub_key, reading_pub_key, delete_pub_key,
                     quota_allocated, when_space_exhausted, auth_key):
                     
    
        timestamp = ut.current_time()
    
        request_string = ut.serialize_request(
            ['CREATE_GROUP', timestamp, self.node_name,
             group_id, owner_id,
             post_access, read_access, delete_access,
             posting_pub_key.key_type, posting_pub_key.public_key,
             reading_pub_key.key_type, reading_pub_key.public_key,
             delete_pub_key.key_type, delete_pub_key.public_key,
             quota_allocated, when_space_exhausted])
    
        signature = auth_key.sign(request_string)
    
        #ut.assert_access(read_access)
        #ut.assert_access(post_access)
        #ut.assert_access(delete_access)
        #ut.assert_public_key(posting_key_type, posting_pub_key)
        #ut.assert_public_key(reading_key_type, reading_pub_key)
        #ut.assert_public_key(delete_key_type, delete_pub_key)
        #ut.assert_exhaustion(when_space_exhausted)
    
        return raw.create_group(
            self.conn,
            timestamp, self.node_name, group_id, owner_id,
            read_access, post_access, delete_access,
            posting_pub_key.key_type, posting_pub_key.public_key,
            reading_pub_key.key_type, reading_pub_key.public_key,
            delete_pub_key.key_type, delete_pub_key.public_key,
            quota_allocated, when_space_exhausted,
            auth_key.public_key_hash, signature)
    
    
    def read_group(self, group_id, owner_id, auth_key):
    
        timestamp = ut.current_time()
    
        request_string = ut.serialize_request(
                ['READ_GROUP', timestamp, self.node_name, group_id, owner_id])
    
        signature = auth_key.sign(request_string)
    
        return raw.read_group(
                self.conn, timestamp, self.node_name, group_id, owner_id,
                auth_key.public_key_hash, signature)
    
    
    def delete_group(self, group_id, owner_id, auth_key):
    
        timestamp = ut.current_time()
    
        request_string = ut.serialize_request(
                ['DELETE_GROUP', timestamp, self.node_name, group_id, owner_id])
    
        signature = auth_key.sign(request_string)
    
        return raw.delete_group(
                self.conn, timestamp, self.node_name, group_id, owner_id,
                auth_key.public_key_hash, signature)
    
    
    #group-quota
    
    def change_group_quota(self, group_id, owner_id, new_size, when_space_exhausted, auth_key):
    
        timestamp = ut.current_time()
    
        request_string = ut.serialize_request(
                ['CHANGE_GROUP_QUOTA', timestamp, self.node_name, group_id, owner_id, new_size, when_space_exhausted])
    
        signature = auth_key.sign(request_string)
    
        return raw.change_group_quota(self.conn,
                timestamp, self.node_name, group_id, owner_id, new_size, when_space_exhausted,
                auth_key.public_key_hash, signature)
    
    
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
    
        return raw.read_group_quota(self.conn, timestamp, self.node_name, group_id, owner_id, read_signature, proof_of_work)
    
        
    
    #last-message-time
    
    def read_last_message_time(self, user_id, auth_key):
        timestamp = ut.current_time()
    
        request_string = ut.serialize_request(
                ['READ_LAST_MESSAGE_TIME', timestamp, self.node_name, user_id])
    
        signature = None
        if auth_key != None:
            signature = auth_key.sign(request_string)
    
        return raw.read_last_message_time(self.conn, timestamp, self.node_name, user_id, auth_key.public_key_hash, signature)
    
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
    
        return raw.read_last_post_time(
                self.conn, timestamp, self.node_name, group_id, owner_id, read_signature, proof_of_work)
    
    
    #message-access
    
    def read_message_access(self, user_id, from_key_hash, auth_key):
    
        timestamp = ut.current_time()
    
        request_string = ut.serialize_request(
                ['READ_MESSAGE_ACCESS', timestamp, self.node_name, user_id, from_key_hash])
    
        signature = auth_key.sign(request_string)
    
        return raw.read_message_access(self.conn,
                timestamp, self.node_name, user_id, from_key_hash, auth_key.public_key_hash, signature)
    
    
    def set_message_access(self, user_id, from_key_hash, access, auth_key):
    
        timestamp = ut.current_time()
    
        request_string = ut.serialize_request(
                ['SET_MESSAGE_ACCESS', timestamp, self.node_name, user_id, from_key_hash, access])
    
        signature = auth_key.sign(request_string)
    
        return raw.set_message_access(self.conn,
                timestamp, self.node_name, user_id, from_key_hash, access, auth_key.public_key_hash, signature)
    
    
    def delete_message_access(self, user_id, from_key_hash, auth_key):
    
        timestamp = ut.current_time()
    
        request_string = ut.serialize_request(
                ['DELETE_MESSAGE_ACCESS', timestamp, self.node_name, user_id, from_key_hash])
    
        signature = auth_key.sign(request_string)
    
        return raw.delete_message_access(self.conn,
                timestamp, self.node_name, user_id, from_key_hash, auth_key.public_key_hash, signature)
    
    
    #message-list
    
    
    def read_message_list(self, user_id, start_time, end_time, max_records, order, auth_key):
    
        timestamp = ut.current_time()
    
        request_string = ut.serialize_request(
                ['READ_MESSAGE_LIST',
                 timestamp, self.node_name, user_id,
                 start_time, end_time, max_records, order])
    
        signature = auth_key.sign(request_string)
    
        return raw.read_message_list(
                self.conn, timestamp, self.node_name, user_id,
                start_time, end_time, max_records, order,
                auth_key.public_key_hash, signature)
    
    
    #message
    
    def read_message(self, user_id, message_id, auth_key):
    
        timestamp = ut.current_time()
    
        request_string = ut.serialize_request(
                ['READ_MESSAGE', timestamp, self.node_name, user_id, message_id])
    
        signature = auth_key.sign(request_string)
    
        return raw.read_message(
                self.conn, timestamp, self.node_name, user_id, message_id,
                auth_key.public_key_hash, signature)
    
    
    def send_message(
            self, to_user, to_user_key_hash,
            from_user, from_key,
            message, proof_of_work_args):
    
        timestamp = ut.current_time()
    
        message_hash = ut.hash_function(message)
    
        from_key_hash = None
        if from_key != None:
            from_key_hash = from_key.public_key_hash
    
        request_string = ut.serialize_request(
                ['SEND_MESSAGE', timestamp, self.node_name,
                 to_user, to_user_key_hash,
                 from_user, from_key_hash,
                 message_hash])
    
        message_id = ut.hash_function(request_string)
    
        from_signature = None
        if from_key != None:
            from_signature = from_key.sign(message_id)
    
        proof_of_work = None
        if proof_of_work_args != None:
            proof_of_work = ut.make_proof_of_work(proof_of_work_args, message_id)
    
        resp = raw.send_message(
                self.conn, timestamp, self.node_name,
                to_user, to_user_key_hash,
                from_user, from_key_hash,
                message_hash,
                message_id, message,
                from_signature, proof_of_work)
    
        return resp, (message_id, timestamp, message_hash, from_signature, proof_of_work)
    
    
    def delete_message(self, user_id, message_id, auth_key):
    
        timestamp = ut.current_time()
    
        request_string = ut.serialize_request(
                ['DELETE_MESSAGE', timestamp, self.node_name, user_id, message_id])
    
        signature = auth_key.sign(request_string)
    
        return raw.delete_message(
                self.conn, timestamp, self.node_name, user_id, message_id,
                auth_key.public_key_hash, signature)
    
    #message-quota
    
    def change_message_quota(self, user_id, new_size, when_space_exhausted, auth_key):
    
        timestamp = ut.current_time()
    
        request_string = ut.serialize_request(
                ['CHANGE_MESSAGE_QUOTA', timestamp, self.node_name, user_id, new_size, when_space_exhausted])
    
        signature = auth_key.sign(request_string)
    
        return raw.change_message_quota(self.conn,
                timestamp, self.node_name, user_id, new_size, when_space_exhausted,
                auth_key.public_key_hash, signature)
    
    
    def read_message_quota(self, user_id, auth_key):
    
        timestamp = ut.current_time()
    
        request_string = ut.serialize_request(
                ['READ_MESSAGE_QUOTA', timestamp, self.node_name, user_id])
    
        signature = auth_key.sign(request_string)
    
        return raw.read_message_quota(self.conn, timestamp, self.node_name, user_id, auth_key.public_key_hash, signature)
    
    
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
     
        return raw.read_post_list(
                self.conn, timestamp, self.node_name, group_id, owner_id,
                start_time, end_time, max_records, order,
                read_signature, proof_of_work)
    
    
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
    
        resp = raw.make_post(
                self.conn, timestamp, self.node_name, group_id, owner_id,
                data_hash, post_id, data,
                post_signature, proof_of_work)
    
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
    
        return raw.read_post(
                self.conn, timestamp, self.node_name,
                group_id, owner_id, post_id,
                read_signature, proof_of_work)
    
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
    
        return raw.delete_post(
                self.conn, timestamp, self.node_name, group_id, owner_id, post_id,
                delete_signature, proof_of_work)
    
    #user
    
    def create_user(self, user_id, pub_key, revoke_date,
                    default_message_access, when_mail_exhausted,
                    quota_size, mail_quota_size,
                    user_class, auth_token):
    
        return raw.create_user(
                self.conn, user_id,
                pub_key.key_type, pub_key.public_key, pub_key.public_key_hash, revoke_date,
                default_message_access, when_mail_exhausted,
                quota_size, mail_quota_size,
                user_class, auth_token)
    
    
    def read_user(self, user_id, auth_key):
    
        timestamp = ut.current_time()
    
        request_string = ut.serialize_request(
                ['READ_USER', timestamp, self.node_name, user_id]) 
    
        signature = auth_key.sign(request_string)
    
        return raw.read_user(
                self.conn, timestamp, self.node_name, user_id,
                auth_key.public_key_hash, signature)
    
    
    def delete_user(self, user_id, auth_key):
    
        timestamp = ut.current_time()
    
        request_string = ut.serialize_request(
                ['DELETE_USER', timestamp, self.node_name, user_id])
    
        signature = auth_key.sign(request_string)
    
        return raw.delete_user(self.conn, timestamp, self.node_name, user_id, auth_key.public_key_hash, signature)
    
    # user-quota
    
    def change_user_quota(self, user_id, new_size, user_class, auth_token, auth_key):
    
        timestamp = ut.current_time()
    
        request_string = ut.serialize_request(
                ['CHANGE_USER_QUOTA', timestamp, self.node_name, user_id, new_size, user_class, auth_token])
    
        signature = auth_key.sign(request_string)
    
        return raw.change_user_quota(self.conn,
                timestamp, self.node_name, user_id, new_size,
                user_class, auth_token,
                auth_key.public_key_hash, signature)
    
    
    
    def read_user_quota(self, user_id, auth_key):
    
        timestamp = ut.current_time()
    
        request_string = ut.serialize_request(
                ['READ_USER_QUOTA', timestamp, self.node_name, user_id])
    
        signature = auth_key.sign(request_string)
    
        return raw.read_user_quota(self.conn, timestamp, self.node_name, user_id, auth_key.public_key_hash, signature)
    
    
    
    # version
    
    
    def read_version(self):
    
        return raw.read_version(self.conn)
    
    
    
    # database
    
    def send_debug(self, query):
    
        return raw.send_debug(self.conn, query)
         
    
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
    
