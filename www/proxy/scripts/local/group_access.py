import squeakspace.common.util as ut
import squeakspace.common.util_http as ht
import squeakspace.proxy.server.db_sqlite3 as db
import squeakspace.common.squeak_ex as ex
import config

def post_handler(environ):

    query = ht.parse_post_request(environ)
    cookies = ht.parse_cookies(environ)

    user_id = ht.get_required_cookie(cookies, 'user_id')
    session_id = ht.get_required_cookie(cookies, 'session_id')

    group_id = ht.get_required(query, 'group_id')
    owner_id = ht.get_required(query, 'owner_id')
    node_name = ht.get_required(query, 'node_name')
    use = ht.get_required(query, 'use')
    access = ht.get_required(query, 'access')
    timestamp = ht.get_optional(query, 'timestamp')

    conn = db.connect(config.db_path)
    try:
        c = db.cursor(conn)
        db.set_local_group_access(c, user_id, session_id, group_id, owner_id, node_name, use, access, timestamp)
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
    node_name = ht.get_required(query, 'node_name')
    use = ht.get_required(query, 'use')


    conn = db.connect(config.db_path)
    try:
        c = db.cursor(conn)
        access = db.read_local_group_access(c, user_id, session_id, group_id, owner_id, node_name, use)

        raise ht.ok_json({'status' : 'ok', 'access' : access})
        
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
    node_name = ht.get_required(query, 'node_name')
    use = ht.get_required(query, 'use')


    conn = db.connect(config.db_path)
    try:
        c = db.cursor(conn)
        db.delete_local_group_access(c, user_id, session_id, group_id, owner_id, node_name, use)
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
