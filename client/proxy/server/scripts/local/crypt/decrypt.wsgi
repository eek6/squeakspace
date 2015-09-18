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

    public_key_hash = ht.get_required(query, 'public_key_hash')
    ciphertext = ht.get_required(query, 'ciphertext')
    passphrase = ht.get_optional(query, 'passphrase')

    conn = db.connect(config.db_path)
    try:
        c = db.cursor(conn)
        plaintext = db.decrypt(c, user_id, session_id, public_key_hash, ciphertext, passphrase)

        raise ht.ok_json({'status' : 'ok', 'plaintext' : plaintext})

    except ex.SqueakException as e:
        raise ht.convert_squeak_exception(e)

    finally:
        db.close(conn)


def main_handler(environ):
    ht.dispatch_on_method(environ, {
            'POST' : post_handler})

def application(environ, start_response):
    return ht.respond_with_handler(environ, start_response, main_handler)
