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

    key_type = ht.get_required(query, 'key_type')
    key_parameters  = ht.get_optional(query, 'key_parameters')
    revoke_date = ht.get_optional(query, 'revoke_date')

    conn = db.connect(config.db_path)
    try:
        c = db.cursor(conn)
        public_key_hash = db.generate_private_key(
                c, user_id, session_id, key_type, key_parameters, revoke_date)
        db.commit(conn)

        raise ht.ok_json({'status' : 'ok', 'public_key_hash' : public_key_hash})

    except ex.SqueakException as e:
        raise ht.convert_squeak_exception(e)

    finally:
        db.close(conn)


def main_handler(environ):
    ht.dispatch_on_method(environ, {
            'POST' : post_handler})

def application(environ, start_response):
    return ht.respond_with_handler(environ, start_response, main_handler)
