


class SqueakStatusCodes:
    bad_request = 'bad_request'
    too_large = 'too_large'
    conflict = 'conflict'
    not_found = 'not_found'
    forbidden = 'forbidden'
    server_error = 'server_error'


class SqueakException(Exception):
    pass


class MalformedTimeStampException(SqueakException):
    type = SqueakStatusCodes.bad_request

    def __init__(self, timestamp, argument):
        self.timestamp = timestamp
        self.argument = argument

    def dict(self):
        return {'status' : 'error', 
                'error_code' : self.type, 
                'reason' : 'malformed timestamp',
                'argument' : self.argument,
                'timestamp' : self.timestamp}

class ExpiredTimeStampException(SqueakException):
    type = SqueakStatusCodes.bad_request

    def __init__(self, timestamp, current_time, acceptable_delay, argument):
        self.timestamp = timestamp
        self.current_time = current_time
        self.acceptable_delay = acceptable_delay
        self.argument = argument

    def dict(self):
        return {'status' : 'error',
                'error_code' : self.type, 
                'reason' : 'expired timestamp',
                'argument' : self.argument,
                'timestamp' : self.timestamp,
                'current_time' : self.current_time,
                'acceptable_delay' : self.acceptable_delay}


class QuotaExceededException(SqueakException):
    type = SqueakStatusCodes.too_large

    def __init__(self, quota_id, quota_allocated, quota_used, size_request, preferred_action):
        self.quota_id = quota_id
        self.quota_allocated = quota_allocated
        self.quota_used = quota_used
        self.size_request = size_request
        self.preferred_action = preferred_action

    def dict(self):
        return {'status' : 'error',
                'error_code' : self.type, 
                'reason' : 'quota exceeded',
                'quota_allocated' : self.quota_allocated,
                'quota_used' : self.quota_used,
                'size_request' : self.size_request}

class QuotaCannotShrinkException(SqueakException):
    type = SqueakStatusCodes.conflict

    def __init__(self, quota_id, quota_allocated, quota_used, size_request):
        self.quota_id = quota_id
        self.quota_allocated = quota_allocated
        self.quota_used = quota_used
        self.size_request = size_request

    def dict(self):
        return {'status' : 'error',
                'error_code' : self.type,
                'reason' : 'quota cannot shrink',
                'quota_allocated' : self.quota_allocated,
                'quota_used' : self.quota_used,
                'size_request' : self.size_request}

class BadArgumentException(SqueakException):
    type = SqueakStatusCodes.bad_request

    def __init__(self, value, argument):
        self.argument = argument
        self.value = value

    def dict(self):
        return {'status' : 'error',
                'error_code' : self.type,
                'reason' : 'bad argument',
                'argument' : self.argument,
                'value' : self.value}

class BadExhaustionException(SqueakException):
    type = SqueakStatusCodes.bad_request

    def __init__(self, value, argument):
        self.value = value
        self.argument = argument

    def dict(self):
        return {'status' : 'error',
                'error_code' : self.type,
                'reason' : 'bad exhaustion',
                'argument' : self.argument,
                'value' : self.value}

class BadHashException(SqueakException):
    type = SqueakStatusCodes.bad_request

    def __init__(self, argument, data, given_hash, expected_hash):
        self.argument = argument
        self.data = data
        self.given_hash = given_hash
        self.expected_hash = expected_hash

    def dict(self):
        return {'status' : 'error',
                'error_code' : self.type, 
                'reason' : 'bad hash',
                'argument' : self.argument,
                'given_hash' : self.given_hash}

class SignatureNullException(SqueakException):
    type = SqueakStatusCodes.bad_request

    def dict(self):
        return {'status' : 'error',
                'error_code' : self.type, 
                'reason' : 'signature null'}

class BadSignatureException(SqueakException):
    type = SqueakStatusCodes.bad_request

    def __init__(self, key_type, public_key, data, bad_signature, argument):
        self.key_type = key_type
        self.public_key = public_key
        self.data = data
        self.bad_signature = bad_signature
        self.argument = argument

    def dict(self):
        return {'status' : 'error',
                'error_code' : self.type, 
                'reason' : 'bad signature',
                'argument' : self.argument,
                'bad_signature' : self.bad_signature}

class BadProofOfWorkException(SqueakException):
    type = SqueakStatusCodes.bad_request

    def __init__(self, parameters, data, bad_proof_of_work, argument):
        self.parameters = parameters
        self.data = data
        self.bad_proof_of_work = bad_proof_of_work
        self.argument = argument

    def dict(self):
        return {'status' : 'error',
                'error_code' : self.type, 
                'reason' : 'bad proof of work',
                'argument' : self.argument,
                'parameters' : self.parameters,
                'bad_proof_of_work' : self.bad_proof_of_work}


class TokenNullException(SqueakException):
    type = SqueakStatusCodes.bad_request

    def __init__(self, argument):
        self.argument = argument

    def dict(self):
        return {'status' : 'error',
                'error_code' : self.type, 
                'reason' : 'token null',
                'argument' : self.argument}

class BadTokenException(SqueakException):
    type = SqueakStatusCodes.bad_request

    def __init__(self, token, data, bad_proof, argument):
        self.token = token # This is secret. Don't disclose it in an error message.
        self.data = data
        self.bad_proof = bad_proof
        self.argument = argument

    def dict(self):
        return {'status' : 'error',
                'error_code' : self.type, 
                'reason' : 'bad token',
                'argument' : self.argument,
                'bad_proof' : self.bad_proof}

class ToUserNameIsNullException(SqueakException):
    type = SqueakStatusCodes.bad_request

    def dict(self):
        return {'status' : 'error',
                'error_code' : self.type, 
                'reason' : 'to username is null'}

class FromUserNameIsNullException(SqueakException):
    type = SqueakStatusCodes.bad_request

    def dict(self):
        return {'status' : 'error',
                'error_code' : self.type, 
                'reason' : 'from username is null'}

class UserNameTakenException(SqueakException):
    type = SqueakStatusCodes.conflict

    def __init__(self, name):
        self.name = name

    def dict(self):
        return {'status' : 'error',
                'error_code' : self.type, 
                'reason' : 'username taken',
                'name' : self.name}

class MailQuotaExceedsUserQuotaException(SqueakException):
    type = SqueakStatusCodes.bad_request

    def __init__(self, user_quota, mail_quota):
        self.user_quota = user_quota
        self.mail_quota = mail_quota

    def dict(self):
        return {'status' : 'error',
                'error_code' : self.type, 
                'reason' : 'mail quota exceeds user quota',
                'user_quota' : self.user_quota,
                'mail_quota' : self.mail_quota}

class UnknownMessageException(SqueakException):
    type = SqueakStatusCodes.not_found

    def __init__(self, user_id, message_id):
        self.user_id = user_id
        self.message_id = message_id

    def dict(self):
        return {'status' : 'error',
                'error_code' : self.type, 
                'reason' : 'unknown message',
                'user_id' : self.user_id,
                'message_id' : self.message_id}

class UnknownUserException(SqueakException):
    type = SqueakStatusCodes.not_found

    def __init__(self, user, argument):
        self.user = user
        self.argument = argument

    def dict(self):
        return {'status' : 'error',
                'error_code' : self.type, 
                'reason' : 'unknown user',
                'argument' : self.argument,
                'user' : self.user}

class UnknownKeyException(SqueakException):
    type = SqueakStatusCodes.not_found

    def __init__(self, public_key_hash):
        self.public_key_hash = public_key_hash

    def dict(self):
        return {'status' : 'error',
                'error_code' : self.type, 
                'reason' : 'unknown key',
                'public_key_hash' : self.public_key_hash}

class KeyDoesNotBelongToIdentityException(SqueakException):
    type = SqueakStatusCodes.forbidden

    def __init__(self, key, identity, identity_type, actual_identity, actual_identity_type):
        self.key = key
        self.identity = identity
        self.identity_type = identity_type
        self.actual_identity = actual_identity
        self.actual_identity_type = actual_identity_type

    def dict(self):
        return {'status' : 'error',
                'error_code' : self.type, 
                'reason' : 'key does not belong to identity',
                'key' : self.key,
                'identity' : self.identity,
                'identity_type' : self.identity_type}

class BlockedException(SqueakException):
    type = SqueakStatusCodes.forbidden

    def dict(self):
        return {'status' : 'error',
                'error_code' : self.type, 
                'reason' : 'blocked'}

class ProofOfWorkRequiredException(SqueakException):
    type = SqueakStatusCodes.bad_request

    def __init__(self, parameters, data, argument):
        self.parameters = parameters
        self.data = data
        self.argument = argument

    def dict(self):
        return {'status' : 'error',
                'error_code' : self.type, 
                'reason' : 'proof of work required',
                'argument' : self.argument,
                'parameters' : self.parameters}

class GroupExistsException(SqueakException):
    type = SqueakStatusCodes.conflict

    def __init__(self, group_id, owner_id):
        self.group_id = group_id
        self.owner_id = owner_id

    def dict(self):
        return {'status' : 'error',
                'error_code' : self.type, 
                'reason' : 'group exists',
                'group_id' : self.group_id,
                'owner_id' : self.owner_id}


class UnknownGroupException(SqueakException):
    type = SqueakStatusCodes.not_found

    def __init__(self, group_id, owner_id):
        self.group_id = group_id
        self.owner_id = owner_id

    def dict(self):
        return {'status' : 'error',
                'error_code' : self.type, 
                'reason' : 'unknown group',
                'group_id' : self.group_id,
                'owner_id' : self.owner_id}

class NotGroupOwnerException(SqueakException):
    type = SqueakStatusCodes.forbidden

    def __init__(self, user_id, group_id, owner_id):
        self.user_id = user_id
        self.group_id = group_id
        self.owner_id = owner_id

    def dict(self):
        return {'status' : 'error',
                'error_code' : self.type, 
                'reason' : 'not group owner'}


class GroupPostInPastException(SqueakException):
    type = SqueakStatusCodes.bad_request

    def __init__(self, timestamp, last_post_time):
        self.timestamp = timestamp
        self.last_post_time = last_post_time

    def dict(self):
        return {'status' : 'error',
                'error_code' : self.type, 
                'reason' : 'group post in past',
                'timestamp' : self.timestamp}

class GroupPostIdExists(SqueakException):
    type = SqueakStatusCodes.conflict

    def __init__(self, post_id, existing_timestamp, group_id, owner_id, existing_data_hash):
        self.post_id = post_id
        self.existing_timestamp = existing_timestamp 
        self.group_id = group_id
        self.owner_id = owner_id
        self.existing_data_hash = existing_data_hash 

    def dict(self):
        return {'status' : 'error',
                'error_code' : self.type, 
                'reason' : 'group post id exists',
                'post_id' : self.post_id,
                'group_id' : self.group_id,
                'owner_id' : self.owner_id}

class UnknownAccessException(SqueakException):
    type = SqueakStatusCodes.bad_request

    def __init__(self, access, argument):
        self.access = access
        self.argument = argument

    def dict(self):
        return {'status' : 'error',
                'error_code' : self.type, 
                'reason' : 'unknown access',
                'argument' : self.argument,
                'access' : self.access}

class UnknownPostException(SqueakException):
    type = SqueakStatusCodes.not_found

    def __init__(self, group_id, owner_id, post_id):
        self.group_id = group_id
        self.owner_id = owner_id
        self.post_id = post_id

    def dict(self):
        return {'status' : 'error',
                'error_code' : self.type, 
                'reason' : 'unknown post',
                'group_id' : self.group_id,
                'owner_id' : self.owner_id,
                'post_id' : self.post_id}


class MalformedProofOfWorkParametersException(SqueakException):
    type = SqueakStatusCodes.bad_request

    def __init__(self, parameters, argument):
        self.parameters = parameters
        self.argument = argument

    def dict(self):
        return {'status' : 'error',
                'error_code' : self.type,
                'reason' : 'malformed proof of work parameters',
                'argument' : self.argument,
                'parameters' : self.parameters}


class UnknownMessageAcessException(SqueakException):
    type = SqueakStatusCodes.not_found

    def __init__(self, user_id, from_key_hash):
        self.user_id = user_id
        self.from_key_hash = from_key_hash

    def dict(self):
        return {'status' : 'error',
                'error_code' : self.type,
                'reason' : 'unknown message access',
                'user_id' : self.user_id,
                'from_key_hash' : self.from_key_hash}


class BadKeyTypeException(SqueakException):
    type = SqueakStatusCodes.bad_request

    def __init__(self, key_type, argument):
        self.key_type = key_type
        self.argument = argument

    def dict(self):
        return {'status' : 'error',
                'error_code' : self.type,
                'reason' : 'bad key type',
                'argument' : self.argument,
                'key_type' : self.key_type}


class KeyHashExistsException(SqueakException):
    type = SqueakStatusCodes.conflict

    def __init__(self, public_key_hash, argument):
        self.public_key_hash = public_key_hash
        self.argument = argument

    def dict(self):
        return {'status' : 'error',
                'error_code' : self.type,
                'reason' : 'key hash exists',
                'argument' : self.argument,
                'public_key_hash' : self.public_key_hash}


class BadPublicKeyHashException(SqueakException):
    type = SqueakStatusCodes.bad_request

    def __init__(self, argument, key_type, public_key, expected_hash, given_hash):
        self.argument = argument
        self.key_type = key_type
        self.public_key = public_key
        self.expected_hash = expected_hash 
        self.given_hash = given_hash

    def dict(self):
        return {'status' : 'error',
                'error_code' : self.type,
                'reason' : 'bad public key hash',
                'argument' : self.argument,
                'key_type' : self.key_type,
                'public_key' : self.public_key,
                'expected_hash' : self.expected_hash,
                'given_hash' : self.given_hash}


class UnsupportedKeyTypeException(SqueakException):
    type = SqueakStatusCodes.bad_request

    def __init__(self, key_type):
        self.key_type = key_type

    def dict(self):
        return {'status' : 'error',
                'error_code' : self.type,
                'reason' : 'unsupported key type',
                'key_type' : self.key_type}


class BadNodeNameException(SqueakException):
    type = SqueakStatusCodes.bad_request

    def __init__(self, given_node_name, node_name):
        self.given_node_name = given_node_name
        self.node_name = node_name

    def dict(self):
        return {'status' : 'error',
                'error_code' : self.type,
                'reason' : 'bad node name',
                'given_node_name' : self.given_node_name,
                'node_name' : self.node_name}

class BadGroupKeyUseException(SqueakException):
    type = SqueakStatusCodes.bad_request

    def __init__(self, use):
        self.use = use

    def dict(self):
        return {'status' : 'error',
                'error_code' : self.type,
                'reason' : 'bad group key use',
                'use' : self.use}
