
import urlparse
import json
import squeak_ex as ex


def json_fun(object):
    #return json.dumps(object)
    return json.dumps(object, indent=4) + '\n'

def respond(environ, start_response, status, content, response_headers=None):
    if response_headers == None:
        response_headers = [('Content-type', 'text/plain'),
                            ('Content-length', str(len(content)))]
    start_response(status, response_headers)
    return [content]

# delete this.
def respond_json(environ, start_response, status, object):
    content = json_fun(content, sort_keys=True)
    return respond(environ, start_response, status, content)

def json_response_headers(body):
    return [('Content-Type', 'application/json'),
            ('Content-Length', str(len(body)))]


class Response(Exception):
    def __init__(self, body, response_headers=None):
        self.body = body
        self.response_headers = response_headers

    def respond(self, environ, start_response):
        return respond(environ, start_response, self.status, self.body, self.response_headers)

class OkResponse(Response):
    status = '200 OK'

class BadRequestResponse(Response):
    status = '400 Bad Request'

class ForbiddenResponse(Response):
    status = '403 Forbidden'

class NotFoundResponse(Response):
    status = '404 Not Found'

class MethodNotAllowedResponse(Response):
    status = '405 Method Not Allowed'

class ConflictResponse(Response):
    status = '409 Conflict'

class LengthRequiredResponse(Response):
    status = '411 Length Required'

class RequestEntityTooLargeResponse(Response):
    status = '413 Request Entity Too Large'

class RequestUriTooLongResponse(Response):
    status = '414 Request-URI Too Long'


class QueryTooLongResponse(RequestEntityTooLargeResponse):
    def __init__(self, query_length, max_length):
        self.query_length = query_length
        self.max_length = max_length
        self.body = json_fun(
                {'status' : 'error',
                 'reason' : 'query too long',
                 'query_length' : query_length,
                 'max_length' : max_length})
        self.response_headers = [('Content-Type', 'application/json'),
                                 ('Content-Length', str(len(self.body)))]

class MalformedQueryStringResponse(BadRequestResponse):
    def __init__(self, query_string):
        self.query_string = query_string
        self.body = json_fun(
                {'status' : 'error',
                 'reason' : 'malformed query string',
                 'query_string' : query_string})
        self.response_headers = [('Content-Type', 'application/json'),
                                 ('Content-Length', str(len(self.body)))]

class ContentLengthRequiredResponse(LengthRequiredResponse):
    def __init__(self):
        self.body = json_fun(
                {'status' : 'error',
                 'reason' : 'Content-Length required'})
        self.response_headers = [('Content-Type', 'application/json'),
                                 ('Content-Length', str(len(self.body)))]

class MalformedContentLengthResponse(BadRequestResponse):
    def __init__(self, content_length):
        self.content_length = content_length
        self.body = json_fun(
                {'status' : 'error',
                 'reason' : 'malformed content length',
                 'content_length' : content_length})
        self.response_headers = [('Content-Type', 'application/json'),
                                 ('Content-Length', str(len(self.body)))]

class ContentLengthTooLargeResponse(RequestEntityTooLargeResponse):
    def __init__(self, content_length, max_length):
        self.content_length = content_length
        self.max_length = max_length
        self.body = json_fun(
                {'status' : 'error',
                 'reason' : 'Content-Length too large',
                 'content_length' : content_length,
                 'max_length' : max_length})
        self.response_headers = [('Content-Type', 'application/json'),
                                 ('Content-Length', str(len(self.body)))]

class IncorrectContentLengthResponse(BadRequestResponse):
    def __init__(self, content_length, actual_body_length):
        self.content_length = content_length
        self.actual_content_length = actual_content_length
        self.body = json_fun(
                {'status' : 'error',
                 'reason' : 'incorrect Content-Length',
                 'content_length' : content_length,
                 'actual_content_length' : actual_content_length})
        self.response_headers = [('Content-Type', 'application/json'),
                                 ('Content-Length', str(len(self.body)))]

class InvalidContentTypeResponse(BadRequestResponse):
    def __init__(self, content_type, supported_content_type):
        self.content_type = content_type
        self.supported_content_type = supported_content_type
        self.body = json_fun(
                {'status' : 'error',
                 'reason' : 'Content-Type invalid',
                 'content_type' : content_type,
                 'supported_content_type' : supported_content_type})
        self.response_headers = [('Content-Type', 'application/json'),
                                 ('Content-Length', str(len(self.body)))]

class MalformedContentResponse(BadRequestResponse):
    # There should be a cut off here. Don't send the content
    # back if it's too large.
    def __init__(self, content):
        self.content = content
        self.body = json_fun(
                {'status' : 'error',
                 'reason' : 'malformed content',
                 'content' : content})
        self.response_headers = [('Content-Type', 'application/json'),
                                 ('Content-Length', str(len(self.body)))]

class FieldRequiredResponse(BadRequestResponse):
    def __init__(self, field):
        self.field = field
        self.body = json_fun(
                {'status' : 'error',
                 'reason' : 'field required',
                 'field' : field})
        self.response_headers = [('Content-Type', 'application/json'),
                                 ('Content-Length', str(len(self.body)))]

class BadFieldResponse(BadRequestResponse):
    def __init__(self, field, value):
        self.field = field
        self.value = value
        self.body = json_fun(
                {'status' : 'error',
                 'reason' : 'bad field',
                 'field' : field,
                 'value' : value})
        self.response_headers = [('Content-Type', 'application/json'),
                                 ('Content-Length', str(len(self.body)))]

class MethodNotAllowedJsonResponse(MethodNotAllowedResponse):
    def __init__(self, method, allow):
        allow_str = ', '.join(allow)
        self.method = method
        self.allow = allow
        self.body = json_fun(
                {'status' : 'error',
                 'reason' : 'method not allowed',
                 'method' : method,
                 'allow' : allow})
        self.response_headers = [('Content-Type', 'application/json'),
                                 ('Content-Length', str(len(self.body))),
                                 ('Allow', allow_str)]

def parse_get_request(environ, max_length = 1024):
    query_string = environ['QUERY_STRING']

    if len(query_string) > max_length:
        raise QueryTooLongResponse(query_length, max_length)

    try:
        # keep_blank_values = False, strict_parsing = True
        return urlparse.parse_qs(query_string, False, True)

    except ValueError:
        raise MalformedQueryStringResponse(query_string)

def parse_post_request(environ, max_length = 200*1024*1024): # 200 MB ok?
    content_length_str = environ.get('CONTENT_LENGTH')

    if content_length_str == None:
        raise ContentLengthRequiredResponse()

    content_length = None

    try:
        content_length = int(content_length_str)
    except ValueError:
        raise MalformedContentLengthResponse(content_length_str)

    if content_length > max_length:
        raise ContentLengthTooLargeResponse(content_length, max_length)

    content_type = environ.get('CONTENT_TYPE')

    supported_content_type = 'application/x-www-form-urlencoded'

    if content_type != supported_content_type:
        raise InvalidContentTypeResponse(content_type, supported_content_type)

    content_input = environ['wsgi.input']

    content = content_input.read(content_length)

    if content_length != len(content):
        raise IncorrectContentLengthResponse(content_length, len(content))

    try:
        return urlparse.parse_qs(content, False, True)

    except ValueError:
        raise MalformedContentResponse(content)

def get_required(query_table, field):
    try:
        return query_table[field][0]

    except KeyError:
        raise FieldRequiredResponse(field)

def get_optional(query_table, field):
    try:
        return query_table[field][0]

    except KeyError:
        return None

def convert_int(string, field):
    try:
        if string != None:
            return int(string)
        else:
            return None
    except ValueError:
        raise BadFieldResponse(field, string)

def convert_bool(string, field):
    if string == None:
        return None

    lower = string.lower()
    if lower == 'true':
        return True
    elif lower == 'false':
        return False
    else:
        raise BadFieldResponse(field, string)

def convert_nat(string, field):
    value = convert_int(string, field)
    if value < 0:
        raise BadFieldResponse(field, string)
    return value



def dispatch_on_method(environ, handlers):
    method = environ['REQUEST_METHOD']

    handler = handlers.get(method)

    if handler == None:
        allow_array = handlers.keys()
        allow_array.sort()
        raise MethodNotAllowedJsonResponse(method, allow_array)

    handler(environ)


def respond_with_handler(environ, start_response, handler):
    response = None
    try:
        response = handler(environ)

    except Response as r:
        response = r

    return response.respond(environ, start_response)

status_conversion_map = {ex.SqueakStatusCodes.bad_request : BadRequestResponse,
                         ex.SqueakStatusCodes.too_large : RequestEntityTooLargeResponse,
                         ex.SqueakStatusCodes.conflict : ConflictResponse,
                         ex.SqueakStatusCodes.not_found : NotFoundResponse,
                         ex.SqueakStatusCodes.forbidden : ForbiddenResponse}

def convert_squeak_exception(e):
    constructor = status_conversion_map[e.type]
    content = json_fun(e.dict())
    headers = json_response_headers(content)
    return constructor(content, headers)

def ok_json(object):
    content = json_fun(object)
    headers = json_response_headers(content)
    return OkResponse(content, headers)

def bad_request(environ, start_response, reason):
    status = '400 Bad Request'
    content = 'Bad Request: ' + reason
    return respond(environ, start_response, status, content)

def conflict(environ, start_response, reason):
    status = '409 Conflict'
    content = 'Conflict: ' + reason
    return respond(environ, start_response, status, content)

def need_content_length(environ, start_response):
    status = '411 Length Required'
    content = 'Length Required'
    return respond(environ, start_response, status, content)

def request_entity_too_large(environ, start_response):
    status = '413 Request Entity Too Large'
    content = 'Request Entity Too Large'
    return respond(environ, start_response, status, content)



