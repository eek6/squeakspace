import util as ut
import util_http as ht
import db_sqlite3 as db
import squeak_ex as ex
import config

def post_handler(environ):

    query = ht.parse_post_request(environ)
    cookies = ht.parse_cookies(environ)

    user_id = ht.get_required_cookie(cookies, 'user_id')
    session_id = ht.get_required_cookie(cookies, 'session_id')

    node_name = ht.get_required(query, 'node_name')
    group_id = ht.get_required(query, 'group_id')
    quota_allocated = ht.convert_int(ht.get_required(query, 'quota_allocated'), 'quota_allocated')
    when_space_exhausted = ht.get_required(query, 'when_space_exhausted')
    public_key_hash = ht.get_required(query, 'public_key_hash')
    passphrase = ht.get_optional(query, 'passphrase')

    conn = db.connect(config.db_path)
    try:
        c = db.cursor(conn)
        resp = db.create_group(c, user_id, session_id,
                               node_name, group_id,
                               quota_allocated, when_space_exhausted,
                               public_key_hash, passphrase)
        db.commit(conn)

        raise ht.ok_json({'status' : 'ok', 'resp' : resp})

    except ex.SqueakException as e:
        raise ht.convert_squeak_exception(e)

    finally:
        db.close(conn)


def get_handler(environ):

    query = ht.parse_get_request(environ)
    cookies = ht.parse_cookies(environ)

    user_id = ht.get_required_cookie(cookies, 'user_id')
    session_id = ht.get_required_cookie(cookies, 'session_id')

    node_name = ht.get_required(query, 'node_name')
    group_id = ht.get_required(query, 'group_id')
    public_key_hash = ht.get_required(query, 'public_key_hash')
    passphrase = ht.get_optional(query, 'passphrase')

    conn = db.connect(config.db_path)
    try:
        c = db.cursor(conn)
        resp = db.read_group(c, user_id, session_id, node_name, group_id, public_key_hash, passphrase)

        raise ht.ok_json({'status' : 'ok', 'resp' : resp})
        
    except ex.SqueakException as e:
        raise ht.convert_squeak_exception(e)

    finally:
        db.close(conn)


def delete_handler(environ):

    query = ht.parse_post_request(environ)
    cookies = ht.parse_cookies(environ)

    user_id = ht.get_required_cookie(cookies, 'user_id')
    session_id = ht.get_required_cookie(cookies, 'session_id')

    node_name = ht.get_required(query, 'node_name')
    group_id = ht.get_required(query, 'group_id')
    public_key_hash = ht.get_required(query, 'public_key_hash')
    passphrase = ht.get_optional(query, 'passphrase')

    conn = db.connect(config.db_path)
    try:
        c = db.cursor(conn)
        resp = db.delete_group(c, user_id, session_id, node_name, group_id, public_key_hash, passphrase)
        db.commit(conn)

        raise ht.ok_json({'status' : 'ok', 'resp' : resp})

    except ex.SqueakException as e:
        raise ht.convert_squeak_exception(e)

    finally:
        db.close(conn)


def main_handler(environ):
    ht.dispatch_on_method(environ, {
            'POST' : post_handler,
            'GET' : get_handler,
            'DELETE' : delete_handler})

def application(environ, start_response):
    return ht.respond_with_handler(environ, start_response, main_handler)
