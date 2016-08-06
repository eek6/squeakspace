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

    public_key_hash = ht.get_required(query, 'public_key_hash')
    plaintext = ht.get_required(query, 'plaintext')

    conn = db.connect(config.db_path)
    try:
        c = db.cursor(conn)
        ciphertext = db.encrypt(c, user_id, session_id, public_key_hash, plaintext)

        raise ht.ok_json({'status' : 'ok', 'ciphertext' : ciphertext})

    except ex.SqueakException as e:
        raise ht.convert_squeak_exception(e)

    finally:
        db.close(conn)


def main_handler(environ):
    ht.dispatch_on_method(environ, {
            'POST' : post_handler})

def application(environ, start_response):
    return ht.respond_with_handler(environ, start_response, main_handler)
