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
    to_user = ht.get_required(query, 'to_user')
    to_user_key_hash = ht.get_optional(query, 'to_user_key_hash')
    from_user_key_hash = ht.get_optional(query, 'from_user_key_hash')
    message  = ht.get_required(query, 'message')
    passphrase = ht.get_optional(query, 'passphrase')
    force_encryption = ht.convert_bool(ht.get_optional(query, 'force_encryption'), 'force_encryption')

    conn = db.connect(config.db_path)
    try:
        c = db.cursor(conn)
        resp, local_gen = db.send_message(c, user_id, session_id,
                                          node_name, to_user, to_user_key_hash, from_user_key_hash,
                                          message, passphrase, force_encryption)
        (message_id, timestamp, message_hash, from_signature, proof_of_work) = local_gen

        db.commit(conn)

        raise ht.ok_json({'status' : 'ok',
                          'resp' : resp,
                          'message_id' : message_id,
                          'timestamp' : timestamp,
                          'message_hash' : message_hash,
                          'from_signature' : from_signature,
                          'proof_of_work' : proof_of_work})

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
    message_id = ht.get_required(query, 'message_id')
    public_key_hash = ht.get_required(query, 'public_key_hash')
    passphrase = ht.get_optional(query, 'passphrase')
    to_key_passphrase = ht.get_optional(query, 'to_key_passphrase')
    decrypt_message = ht.convert_bool(ht.get_optional(query, 'decrypt_message'), 'decrypt_message')

    conn = db.connect(config.db_path)
    try:
        c = db.cursor(conn)
        resp, validation = db.read_message(c, user_id, session_id, node_name, message_id,
                                           public_key_hash, passphrase,
                                           to_key_passphrase, decrypt_message)

        raise ht.ok_json({'status' : 'ok',
                          'resp' : resp,
                          'validation' : validation})
        
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
    message_id  = ht.get_required(query, 'message_id')
    public_key_hash = ht.get_required(query, 'public_key_hash')
    passphrase = ht.get_optional(query, 'passphrase')

    conn = db.connect(config.db_path)
    try:
        c = db.cursor(conn)
        resp = db.delete_message(c, user_id, session_id, node_name, message_id, public_key_hash, passphrase)
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
