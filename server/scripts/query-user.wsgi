import json
import util as ut
import util_http as ht
import config
import squeak_ex as ex
import db_sqlite3 as db



def get_handler(environ):

    query = ht.parse_get_request(environ)

    node_name = ht.get_required(query, 'node_name')
    user_id = ht.get_required(query, 'user_id')

    conn = db.connect(config.db_path)
    try:
        c = db.cursor(conn)
        user_exists = db.query_user(c, node_name, user_id)

        raise ht.ok_json({'status' : 'ok', 'user_exists' : user_exists})

    except ex.SqueakException as e:
        raise ht.convert_squeak_exception(e)

    finally:
        db.close(conn)


def main_handler(environ):
    ht.dispatch_on_method(environ, {
            'GET' : get_handler})

def application(environ, start_response):
    return ht.respond_with_handler(environ, start_response, main_handler)

