import util as ut
import util_http as ht
import config_proto

def get_handler(environ):
    raise ht.ok_json({'status' : 'ok',
                      'version' : config_proto.version})

def main_handler(environ):
    ht.dispatch_on_method(environ, {'GET' : get_handler})

def application(environ, start_response):
    return ht.respond_with_handler(environ, start_response, main_handler)
