import squeakspace.common.util as ut
import squeakspace.common.util_http as ht
import squeakspace.server.db_sqlite3 as db

def get_handler(environ):

    query = ht.parse_get_request(environ)

    node_name = ht.get_required(query, 'node_name')
    user_class = ht.get_optional(query, 'user_class')

    quota_available = db.get_quota_available(node_name, user_class)

    raise ht.ok_json(
            {'status' : 'ok',
             'quota_available' : quota_available})

def main_handler(environ):
    ht.dispatch_on_method(environ, {'GET' : get_handler})

def application(environ, start_response):
    return ht.respond_with_handler(environ, start_response, main_handler)
