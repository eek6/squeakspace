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

    method  = ht.get_required(query, 'method')
    password  = ht.get_optional(query, 'password')
    public_key_hash  = ht.get_optional(query, 'public_key_hash')

    conn = db.connect(config.db_path)
    try:
        c = db.cursor(conn)
        db.set_password(c, user_id, session_id, method, password, public_key_hash)
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

    conn = db.connect(config.db_path)
    try:
        c = db.cursor(conn)
        params = db.get_password()

        raise ht.ok_json({'status' : 'ok', 'params' : params})
        
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
