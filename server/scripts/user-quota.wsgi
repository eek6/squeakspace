import json
import util as ut
import util_http as ht
import config
import squeak_ex as ex
import db_sqlite3 as db



def post_handler(environ):

    query = ht.parse_post_request(environ)

    timestamp = ht.convert_int(ht.get_required(query, 'timestamp'), 'timestamp')
    node_name = ht.get_required(query, 'node_name')
    user_id = ht.get_required(query, 'user_id')
    new_size = ht.convert_int(ht.get_required(query, 'new_size'), 'new_size')
    user_class = ht.get_optional(query, 'user_class')
    auth_token = ht.get_optional(query, 'auth_token')

    public_key_hash = ht.get_required(query, 'public_key_hash')
    signature = ht.get_required(query, 'signature')

    conn = db.connect(config.db_path)
    try:
        c = db.cursor(conn)
        db.change_user_quota(c,
                timestamp, node_name, user_id, new_size,
                user_class, auth_token,
                public_key_hash, signature)
        db.commit(conn)

        raise ht.ok_json({'status' : 'ok'})

    except ex.SqueakException as e:
        raise ht.convert_squeak_exception(e)

    finally:
        db.close(conn)


def get_handler(environ):

    query = ht.parse_get_request(environ)

    timestamp = ht.convert_int(ht.get_required(query, 'timestamp'), 'timestamp')
    node_name = ht.get_required(query, 'node_name')
    user_id = ht.get_required(query, 'user_id')
    public_key_hash = ht.get_required(query, 'public_key_hash')
    signature = ht.get_required(query, 'signature')

    conn = db.connect(config.db_path)
    try:
        c = db.cursor(conn)
        quota_obj = db.read_user_quota(c, timestamp, node_name, user_id, public_key_hash, signature)

        raise ht.ok_json({'status' : 'ok', 'user_quota' : quota_obj})

    except ex.SqueakException as e:
        raise ht.convert_squeak_exception(e)

    finally:
        db.close(conn)


def main_handler(environ):
    ht.dispatch_on_method(environ, {
            'POST' : post_handler,
            'GET' : get_handler})

def application(environ, start_response):
    return ht.respond_with_handler(environ, start_response, main_handler)

