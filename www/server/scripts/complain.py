import squeakspace.common.util as ut
import squeakspace.common.util_http as uh

def post_handler(environ):
    raise uh.ok_json({'handler' : 'post'})

def get_handler(environ):
    raise uh.ok_json({'handler' : 'get'})

def delete_handler(environ):
    raise uh.ok_json({'handler' : 'delete'})

def main_handler(environ):
    uh.dispatch_on_method(environ, {
            'POST' : post_handler,
            'GET' : get_handler,
            'DELETE' : delete_handler})

def application(environ, start_response):
    return uh.respond_with_handler(environ, start_response, main_handler)

