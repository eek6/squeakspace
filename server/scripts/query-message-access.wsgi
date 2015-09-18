import util as ut
import util_http as ht
import db_sqlite3 as db
import squeak_ex as ex
import config

def get_handler(environ):

    query = ht.parse_get_request(environ)

    timestamp = ht.convert_int(ht.get_required(query, 'timestamp'), 'timestamp')
    node_name = ht.get_required(query, 'node_name')
    to_user = ht.get_required(query, 'to_user')
    from_user = ht.get_required(query, 'from_user')
    from_user_key_hash = ht.get_required(query, 'from_user_key_hash')
    from_user_key_sig = ht.get_required(query, 'from_user_key_sig')

    conn = db.connect(config.db_path)
    try:
        c = db.cursor(conn)
        message_access = db.query_message_access(c,
                timestamp, node_name, to_user, from_user, from_user_key_hash, from_user_key_sig)

        raise ht.ok_json({'status' : 'ok', 'message_access' : message_access})

    except ex.SqueakException as e:
        raise ht.convert_squeak_exception(e)

    finally:
        db.close(conn)

def main_handler(environ):
    ht.dispatch_on_method(environ, {
            'GET' : get_handler})

def application(environ, start_response):
    return ht.respond_with_handler(environ, start_response, main_handler)

