import squeakspace.common.util as ut
import squeakspace.common.util_http as ht
import squeakspace.server.db_sqlite3 as db
import squeakspace.common.squeak_ex as ex
import config

def post_handler(environ):

    query = ht.parse_post_request(environ)

    timestamp = ht.convert_int(ht.get_required(query, 'timestamp'), 'timestamp')
    node_name = ht.get_required(query, 'node_name')
    user_id = ht.get_required(query, 'user_id')
    new_size = ht.convert_int(ht.get_optional(query, 'new_size'), 'new_size')
    public_key_hash = ht.get_required(query, 'public_key_hash')
    signature = ht.get_required(query, 'signature')

    conn = db.connect(config.db_path)
    try:
        c = db.cursor(conn)
        db.change_max_message_size(c,
                timestamp, node_name, user_id, new_size,
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
    to_user = ht.get_required(query, 'to_user')
    from_user = ht.get_optional(query, 'from_user')
    from_user_key_hash = ht.get_optional(query, 'from_user_key_hash')
    from_user_key_sig = ht.get_optional(query, 'from_user_key_sig')
    
    conn = db.connect(config.db_path)
    try:
        c = db.cursor(conn)
        max_message_size = db.read_max_message_size(c,
                timestamp, node_name, to_user, from_user, from_user_key_hash, from_user_key_sig)

        raise ht.ok_json({'status' : 'ok', 'max_message_size' : max_message_size})

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

