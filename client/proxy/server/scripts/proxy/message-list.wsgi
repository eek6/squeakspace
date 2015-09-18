import util as ut
import util_http as ht
import db_sqlite3 as db
import squeak_ex as ex
import config


def get_handler(environ):

    query = ht.parse_get_request(environ)
    cookies = ht.parse_cookies(environ)

    user_id = ht.get_required_cookie(cookies, 'user_id')
    session_id = ht.get_required_cookie(cookies, 'session_id')

    node_name = ht.get_required(query, 'node_name')
    start_time = ht.convert_int(ht.get_optional(query, 'start_time'), 'start_time')
    end_time = ht.convert_int(ht.get_optional(query, 'end_time'), 'end_time')
    max_records = ht.convert_int(ht.get_optional(query, 'max_records'), 'max_records')
    order = ht.get_optional(query, 'order')
    public_key_hash = ht.get_required(query, 'public_key_hash')
    passphrase  = ht.get_optional(query, 'passphrase ')

    conn = db.connect(config.db_path)
    try:
        c = db.cursor(conn)
        resp = db.read_message_list(c, user_id, session_id,
                                    node_name, start_time, end_time, max_records, order,
                                    public_key_hash, passphrase)

        raise ht.ok_json({'status' : 'ok', 'resp' : resp})
        
    except ex.SqueakException as e:
        raise ht.convert_squeak_exception(e)

    finally:
        db.close(conn)


def main_handler(environ):
    ht.dispatch_on_method(environ, {
            'GET' : get_handler})

def application(environ, start_response):
    return ht.respond_with_handler(environ, start_response, main_handler)
