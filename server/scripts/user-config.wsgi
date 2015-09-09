import util as ut
import util_http as ht

def post_handler(environ):
    raise ht.ok_json({'handler' : 'post'})

def get_handler(environ):
    raise ht.ok_json({'handler' : 'get'})

def delete_handler(environ):
    raise ht.ok_json({'handler' : 'delete'})

def main_handler(environ):
    ht.dispatch_on_method(environ, {
            'POST' : post_handler,
            'GET' : get_handler,
            'DELETE' : delete_handler})

def application(environ, start_response):
    return ht.respond_with_handler(environ, start_response, main_handler)

