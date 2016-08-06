import squeakspace.common.util as ut
import squeakspace.common.util_http as ht
import squeakspace.proxy.server.db_sqlite3 as db
import squeakspace.common.squeak_ex as ex
import config

import Cookie

def post_handler(environ):

    query = ht.parse_post_request(environ)

    user_id = ht.get_required(query, 'user_id')
    password = ht.get_required(query, 'password')

    conn = db.connect(config.db_path)
    try:
        c = db.cursor(conn)
        session = db.create_local_user(c, user_id, password)

        cookies = Cookie.SimpleCookie()
        cookies['user_id'] = session['user_id']
        cookies['user_id']['path'] = '/'
        cookies['session_id'] = session['session_id']
        cookies['session_id']['path'] = '/'

        db.commit(conn)

        raise ht.ok_json({'status' : 'ok', 'session' : session}).attach_cookies(cookies)

    except ex.SqueakException as e:
        raise ht.convert_squeak_exception(e)

    finally:
        db.close(conn)


def delete_handler(environ):

    cookies = ht.parse_cookies(environ)

    user_id = ht.get_required_cookie(cookies, 'user_id')
    session_id = ht.get_required_cookie(cookies, 'session_id')

    conn = db.connect(config.db_path)
    try:
        c = db.cursor(conn)
        db.delete_local_user(c, user_id, session_id)
        db.commit(conn)

        cookies = ['user_id', 'session_id']

        raise ht.ok_json({'status' : 'ok'}).clear_cookies(cookies)

    except ex.SqueakException as e:
        raise ht.convert_squeak_exception(e)

    finally:
        db.close(conn)


def main_handler(environ):
    ht.dispatch_on_method(environ, {
            'POST' : post_handler,
            'DELETE' : delete_handler})

def application(environ, start_response):
    return ht.respond_with_handler(environ, start_response, main_handler)
