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

    other_user_id = ht.get_required(query, 'other_user_id')
    public_key_hash = ht.get_required(query, 'public_key_hash')
    trust_score = ht.get_required(query, 'trust_score')

    conn = db.connect(config.db_path)
    try:
        c = db.cursor(conn)
        db.assign_other_user_key(c, user_id, session_id, other_user_id, public_key_hash, trust_score)
        db.commit(conn)

        raise ht.ok_json({'status' : 'ok'})

    except ex.SqueakException as e:
        raise ht.convert_squeak_exception(e)

    finally:
        db.close(conn)


def get_handler(environ):

    query = ht.parse_get_request(environ)
    cookies = ht.parse_cookies(environ)

    user_id = ht.get_required_cookie(cookies, 'user_id')
    session_id = ht.get_required_cookie(cookies, 'session_id')

    other_user_id = ht.get_required(query, 'other_user_id')
    public_key_hash = ht.get_required(query, 'public_key_hash')

    conn = db.connect(config.db_path)
    try:
        c = db.cursor(conn)
        key = db.read_other_user_key(c, user_id, session_id, other_user_id, public_key_hash)

        raise ht.ok_json({'status' : 'ok', 'key' : key})
        
    except ex.SqueakException as e:
        raise ht.convert_squeak_exception(e)

    finally:
        db.close(conn)


def delete_handler(environ):

    query = ht.parse_post_request(environ)
    cookies = ht.parse_cookies(environ)

    user_id = ht.get_required_cookie(cookies, 'user_id')
    session_id = ht.get_required_cookie(cookies, 'session_id')

    other_user_id = ht.get_required(query, 'other_user_id')
    public_key_hash = ht.get_required(query, 'public_key_hash')

    conn = db.connect(config.db_path)
    try:
        c = db.cursor(conn)
        db.delete_other_user_key(c, user_id, session_id, other_user_id, public_key_hash)
        db.commit(conn)

        raise ht.ok_json({'status' : 'ok'})

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
