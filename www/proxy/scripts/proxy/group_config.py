import squeakspace.common.util as ut
import squeakspace.common.util_http as ht
import squeakspace.proxy.server.db_sqlite3 as db
import squeakspace.common.squeak_ex as ex
import config

def post_handler(environ):
    raise ht.ok_json({'status' : 'not_implemented'})

def get_handler(environ):
    raise ht.ok_json({'status' : 'not_implemented'})

def delete_handler(environ):
    raise ht.ok_json({'status' : 'not_implemented'})

def main_handler(environ):
    ht.dispatch_on_method(environ, {
            'POST' : post_handler,
            'GET' : get_handler,
            'DELETE' : delete_handler})

def application(environ, start_response):
    return ht.respond_with_handler(environ, start_response, main_handler)
