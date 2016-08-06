import squeakspace.client.client as cl
import squeakspace.client.client_raw as raw
import squeakspace.common.util as ut

# This didn't work out. I'm going to get rid of it.

class User:
    def __init__(self, user_id, key, revoke_date,
                 default_mail_access, when_mail_exhausted,
                 quota_size, mail_quota_size,
                 max_message_size,
                 user_class, auth_token):

        self.user_id = user_id
        self.key = key
        self.revoke_date = revoke_date
        self.default_mail_access = default_mail_access
        self.when_mail_exhausted = when_mail_exhausted
        self.quota_size = quota_size
        self.mail_quota_size = mail_quota_size
        self.max_message_size = max_message_size
        self.user_class = user_class
        self.auth_token = auth_token

    def create(self, client):
        return client.create_user(
                self.user_id, self.key, self.revoke_date,
                self.default_mail_access, self.when_mail_exhausted,
                self.quota_size, self.mail_quota_size,
                self.max_message_size,
                self.user_class, self.auth_token)

    def read(self, client):
        return client.read_user(self.user_id, self.key)

    def delete(self, client):
        return client.delete_user(self.user_id, self.key)


#class Group:
#    def __init__(self, group_id, owner_id,
#                 read_access, post_access, delete_access,
#                 posting_key_type, posting_pub_key,
#                 reading_key_type, reading_pub_key,
#                 delete_key_type, delete_pub_key,
#                 quota_allocated, when_space_allocated,
#                 public_key_hash, private_key):
#        self.group_id = group_id
#        self.owner_id = owner_id
#        self.read_access = read_access
#        self.post_access = post_access
#        self.delete_access = delete_access
#        self.posting_key_type = posting_key_type
#        self.posting_pub_key = posting_pub_key
#        self.reading_key_type = reading_key_type
#        self.reading_pub_key = reading_pub_key
#        self.delete_key_type = delete_key_type
#        self.delete_pub_key = delete_pub_key
#        self.quota_allocated = quota_allocated
#        self.when_space_allocated = when_space_allocated
#        self.public_key_hash = public_key_hash
#        self.private_key = private_key
#
#    def create(self, conn):
#        return cl.create_group(conn,
#                self.group_id, self.owner_id,
#                self.read_access, self.post_access, self.delete_access,
#                self.posting_key_type, self.posting_pub_key,
#                self.reading_key_type, self.reading_pub_key,
#                self.delete_key_type, self.delete_pub_key,
#                self.quota_allocated, self.when_space_allocated,
#                self.key_type, self.public_key_hash, self.private_key)
#
#    def delete(self, public_key_hash, private_key):
#        return cl.delete_group(conn, self.group_id, self.owner_id, public_key_hash, private_key)
#


#
#class Message:
#    def __init__(self, message_id, timestamp,
#                 to_user, to_user_key,
#                 from_user, from_user_key,
#                 message, message_hash,
#                 from_signature, proof_of_work)
#        self.message_id = message_id
#        self.timestamp = timestamp
#        self.to_user = to_user
#        self.to_user_key = to_user_key
#        self.from_user = from_user
#        self.from_user_key = from_user_key
#        self.message = message
#        self.message_hash = message_hash
#        self.from_signature = from_signature
#        self.proof_of_work = proof_of_work
#
#    # Use ClientMessage.send instead.
#    def send(self, conn):
#        return raw.send_message(
#                conn, self.timestamp,
#                self.to_user, self.to_user_key_hash,
#                self.from_user, self.from_user_key_hash,
#                self.message_hash, self.message_id, self.message,
#                self.from_signature, self.proof_of_work)
#
#    def read(self, conn, public_key_hash, private_key):
#        return cl.read_message(conn, self.to_user, self.message_id, public_key_hash, private_key)
#
#    def delete(self, conn, public_key_hash, private_key):
#        return cl.delete_message(conn, self.to_user, self.message_id, public_key_hash, private_key)
#
#
## A message that has not yet been sent.
#class ClientMessage:
#    def __init__(self,
#                 to_user, to_user_key_hash,
#                 from_user, from_user_key_hash,
#                 message,
#                 from_private_key, proof_of_work_args):
#        self.to_user = to_user
#        self.to_user_key_hash = to_user_key_hash
#        self.from_user = from_user
#        self.from_user_key_hash = from_user_key_hash
#        self.message = message
#        self.from_private_key = from_private_key
#        self.proof_of_work_args = proof_of_work_args
#
#
#    def send(self, conn):
#        (resp, gen_fields) = cl.send_message(
#                conn, self.to_user, self.to_user_key_hash,
#                self.from_user, self.from_user_key_hash,
#                self.message,
#                self.from_private_key, self.proof_of_work_args)
#
#        (message_id, timestamp, message_hash,
#         from_signature, proof_of_work) = gen_fields
#
#        sent_message = Message(message_id, timestamp,
#                               self.to_user, self.to_user_key,
#                               self.from_user, self.from_user_key,
#                               self.message, message_hash,
#                               from_signature, proof_of_work)
#
#        return resp, sent_message
#
#    def read(self, conn, public_key_hash, private_key):
#        return cl.read_message(conn, self.to_user, self.message_id, public_key_hash, private_key)
#
#    def delete(self, conn, public_key_hash, private_key)
#        return cl.delete_message(conn, self.to_user, self.message_id, public_key_hash, private_key)
#
#
#class Quota:
#    def __init__(self, ):
#
#
#
#class Group:
#    def __init__(self, group_id, owner_id, post_access, read_access, delete_access, posting_pub_key, reading_pub_key, delete_pub_key, quota, last_post_time):
#
#{'group_id' : group_id,
#            'owner_id' : owner_id,
#            'post_access' : post_access,
#            'read_access' : read_access,
#            'delete_access' : delete_access,
#            'posting_pub_key' : posting_pub_key,
#            'reading_pub_key' : reading_pub_key,
#            'delete_pub_key' : delete_pub_key,
#            'quota' : quota_obj,
#            'last_post_time' : last_post_time}
