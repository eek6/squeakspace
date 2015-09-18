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

    group_id = ht.get_required(query, 'group_id')
    owner_id = ht.get_required(query, 'owner_id')
    key_use = ht.get_required(query, 'key_use')
    public_key_hash = ht.get_required(query, 'public_key_hash')


    conn = db.connect(config.db_path)
    try:
        c = db.cursor(conn)
        db.assign_local_group_key(c, user_id, session_id, group_id, owner_id, key_use, public_key_hash)
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

    group_id = ht.get_required(query, 'group_id')
    owner_id = ht.get_required(query, 'owner_id')
    key_use = ht.get_required(query, 'key_use')


    conn = db.connect(config.db_path)
    try:
        c = db.cursor(conn)
        key = db.read_local_group_key(c, user_id, session_id, group_id, owner_id, key_use)

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

    group_id = ht.get_required(query, 'group_id')
    owner_id = ht.get_required(query, 'owner_id')
    key_use = ht.get_required(query, 'key_use')


    conn = db.connect(config.db_path)
    try:
        c = db.cursor(conn)
        db.delete_local_group_key(c, user_id, session_id, group_id, owner_id, key_use)
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
