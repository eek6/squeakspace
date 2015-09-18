
# squeak client exceptions

import squeak_ex as ex

class SqueakClientException(ex.SqueakException):
    pass

class BadSessionIdException(SqueakClientException):
    type = ex.SqueakStatusCodes.bad_request

    def __init__(self, user_id, session_id):
        self.user_id = user_id
        self.session_id = session_id

    def dict(self):
        return {'status' : 'error',
                'error_code' : self.type,
                'reason' : 'bad session id',
                'user_id' : self.user_id,
                'session_id' : self.session_id}

class BadKeyUseException(SqueakClientException):
    type = ex.SqueakStatusCodes.bad_request

    def __init__(self, key_use):
        self.key_use = key_use

    def dict(self):
        return {'status' : 'error',
                'error_code' : self.type,
                'reason' : 'bad key use',
                'key_use' : self.key_use}

class BadKeyParametersException(SqueakClientException):
    type = ex.SqueakStatusCodes.bad_request

    def __init__(self, key_parameters):
        self.key_parameters = key_parameters

    def dict(self):
        return {'status' : 'error',
                'error_code' : self.type,
                'reason' : 'bad key parameters',
                'key_parameters' : self.key_parameters}

class BadPasswordParametersException(SqueakClientException):
    type = ex.SqueakStatusCodes.bad_request

    def __init__(self, method, password, public_key_hash):
        self.method = method
        self.password = password
        self.public_key_hash = public_key_hash

    def dict(self):
        return {'status' : 'error',
                'error_code' : self.type,
                'reason' : 'bad key parameters',
                'method' : self.method,
                'password' : self.password,
                'public_key_hash' : self.public_key_hash}

class GroupKeyNotFoundException(SqueakClientException):
    type = ex.SqueakStatusCodes.not_found

    def __init__(self, user_id, group_id, owner_id, key_use):
        self.user_id = user_id
        self.group_id = group_id
        self.owner_id = owner_id
        self.key_use = key_use

    def dict(self):
        return {'status' : 'error',
                'error_code' : self.type,
                'reason' : 'group key not found',
                'group_id' : self.group_id,
                'owner_id' : self.owner_id,
                'key_use' : self.key_use}


class GroupKeyExistsException(SqueakClientException):
    type = ex.SqueakStatusCodes.conflict

    def __init__(self, user_id, group_id, owner_id, key_use):
        self.user_id = user_id
        self.group_id = group_id
        self.owner_id = owner_id
        self.key_use = key_use

    def dict(self):
        return {'status' : 'error',
                'error_code' : self.type,
                'reason' : 'group key exists',
                'user_id' : self.user_id,
                'owner_id' : self.owner_id,
                'group_id' : self.group_id,
                'key_use' : self.key_use}


class UserKeyNotFoundException(SqueakClientException):
    type = ex.SqueakStatusCodes.not_found

    def __init__(self, user_id, public_key_hash):
        self.user_id = user_id
        self.public_key_hash = public_key_hash

    def dict(self):
        return {'status' : 'error',
                'error_code' : self.type,
                'reason' : 'user key not found',
                'user_id' : self.user_id,
                'public_key_hash' : self.public_key_hash}


class UserKeyExistsException(SqueakClientException):
    type = ex.SqueakStatusCodes.conflict

    def __init__(self, user_id, public_key_hash):
        self.user_id = user_id
        self.public_key_hash = public_key_hash

    def dict(self):
        return {'status' : 'error',
                'error_code' : self.type,
                'reason' : 'user key exists',
                'user_id' : self.user_id,
                'public_key_hash' : self.public_key_hash}


class OtherUserKeyNotFoundException(SqueakClientException):
    type = ex.SqueakStatusCodes.not_found

    def __init__(self, local_user_id, user_id, public_key_hash):
        self.local_user_id = local_user_id
        self.user_id = user_id
        self.public_key_hash = public_key_hash

    def dict(self):
        return {'status' : 'error',
                'error_code' : self.type,
                'reason' : 'other user key not found',
                'local_user_id' : self.local_user_id,
                'user_id' : self.user_id,
                'public_key_hash' : self.public_key_hash}


class KeyNotFoundException(SqueakClientException):
    type = ex.SqueakStatusCodes.not_found

    def __init__(self, user_id, public_key_hash, key_class):
        self.user_id = user_id
        self.public_key_hash = public_key_hash
        self.key_class = key_class

    def dict(self):
        return {'status' : 'error',
                'error_code' : self.type,
                'reason' : 'private key not found',
                'user_id' : self.user_id,
                'public_key_hash' : self.public_key_hash,
                'key_class' : self.key_class}

class KeyExistsException(SqueakClientException):
    type = ex.SqueakStatusCodes.conflict

    def __init__(self, user_id, public_key_hash, key_class):
        self.user_id = user_id
        self.public_key_hash = public_key_hash
        self.key_class = key_class

    def dict(self):
        return {'status' : 'error',
                'error_code' : self.type,
                'reason' : 'key exists',
                'user_id' : self.user_id,
                'public_key_hash' : self.public_key_hash,
                'key_class' : self.key_class}

class UnregisteredUserException(SqueakClientException):
    type = ex.SqueakStatusCodes.bad_request

    def __init__(self, user_id):
        self.user_id = user_id

    def dict(self):
        return {'status' : 'error',
                'error_code' : self.type,
                'reason' : 'unregistered user',
                'user_id' : self.user_id}

class BadPasswordException(SqueakClientException):
    type = ex.SqueakStatusCodes.bad_request

    def __init__(self, user_id, password):
        self.user_id = user_id
        self.password = password

    def dict(self):
        return {'status' : 'error',
                'error_code' : self.type,
                'reason' : 'bad password',
                'user_id' : self.user_id,
                'password' : self.password}

class LocalUserExistsException(SqueakClientException):
    type = ex.SqueakStatusCodes.conflict

    def __init__(self, user_id):
        self.user_id = user_id

    def dict(self):
        return {'status' : 'error',
                'error_code' : self.type,
                'reason' : 'local user exists',
                'user_id' : self.user_id}


class BadUrlException(SqueakClientException):
    type = ex.SqueakStatusCodes.bad_request

    def __init__(self, url):
        self.url = url

    def dict(self):
        return {'status' : 'error',
                'error_code' : self.type,
                'reason' : 'bad url',
                'url' : self.url}


class NodeAddrNotFoundException(SqueakClientException):
    type = ex.SqueakStatusCodes.not_found
    
    def __init__(self, user_id, node_name):
        self.user_id = user_id
        self.node_name = node_name

    def dict(self):
        return {'status' : 'error',
                'error_code' : self.type,
                'reason' : 'node addr not found',
                'user_id' : self.user_id,
                'node_name' : self.node_name}


class ConnectionException(SqueakClientException):
    type = ex.SqueakStatusCodes.server_error

    def __init__(self, user_id, node_name, url, exception_type, exception_str):
        self.user_id = user_id
        self.node_name = node_name
        self.url = url
        self.exception_type = exception_type
        self.exception_str = exception_str

    def dict(self):
        return {'status' : 'error',
                'error_code' : self.type,
                'reason' : 'connection',
                'user_id' : self.user_id,
                'node_name' : self.node_name,
                'url' : self.url,
                'exception_type' : self.exception_type,
                'exception_str' : self.exception_str}



class LocalGroupAccessNotFoundException(SqueakClientException):
    type = ex.SqueakStatusCodes.not_found

    def __init__(self, user_id, group_id, owner_id, use):
        self.user_id = user_id
        self.group_id = group_id
        self.owner_id = owner_id
        self.use = use

    def dict(self):
        return {'status' : 'error',
                'error_code' : self.type,
                'reason' : 'local group access not found',
                'user_id' : self.user_id,
                'group_id' : self.group_id,
                'owner_id' : self.owner_id,
                'use' : self.use}


class LocalMessageAccessNotFoundException(SqueakClientException):
    type = ex.SqueakStatusCodes.not_found

    def __init__(self, user_id, to_user, from_user_key_hash):
        self.user_id = user_id
        self.to_user = to_user
        self.from_user_key_hash = from_user_key_hash
        
    def dict(self):
        return {'status' : 'error',
                'error_code' : self.type,
                'reason' : 'local message access not found',
                'user_id' : self.user_id,
                'to_user' : self.to_user,
                'from_user_key_hash' : self.from_user_key_hash}





#class BadBoolException(SqueakClientException):
#    type = ex.SqueakStatusCodes.bad_request
#
#    def __init__(self, value, argument):
#        self.argument = argument
#        self.value = value
#
#    def dict(self):
#        return {'status' : 'error',
#                'error_code' : self.type,
#                'reason' : 'bad bool',
#                'argument' : self.argument,
#                'value' : self.value}
#
#def assert_bool(value, argument):
#    if value != 'true' and value != 'false':
#        raise BadBoolException(value, argument)



