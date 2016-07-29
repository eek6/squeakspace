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
    owner_id = ht.get_required(query, 'owner_id')
    data = ht.get_required(query, 'data')
    passphrase = ht.get_optional(query, 'passphrase')
    force_encryption = ht.convert_bool(ht.get_optional(query, 'force_encryption'), 'force_encryption')

    conn = db.connect(config.db_path)
    try:
        c = db.cursor(conn)
        resp, local_gen = db.make_post(c, user_id, session_id, node_name, group_id, owner_id, data,
                                       passphrase, force_encryption)

        (post_id, timestamp, data_hash, post_signature, proof_of_work) = local_gen

        db.commit(conn)

        raise ht.ok_json({'status' : 'ok',
                          'resp' : resp,
                          'post_id' : post_id,
                          'timestamp' : timestamp,
                          'data_hash' : data_hash,
                          'post_signature' : post_signature,
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
    group_id = ht.get_required(query, 'group_id')
    owner_id = ht.get_required(query, 'owner_id')
    post_id = ht.get_required(query, 'post_id')
    passphrase = ht.get_optional(query, 'passphrase')
    decrypt_post = ht.convert_bool(ht.get_optional(query, 'decrypt_post'), 'decrypt_post')

    conn = db.connect(config.db_path)
    try:
        c = db.cursor(conn)
        resp, validation = db.read_post(c,
                user_id, session_id, node_name, group_id, owner_id, post_id,
                passphrase, decrypt_post)

        raise ht.ok_json({'status' : 'ok', 'resp' : resp, 'validation' : validation})
        
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
    owner_id = ht.get_required(query, 'owner_id')
    post_id = ht.get_required(query, 'post_id')
    passphrase = ht.get_optional(query, 'passphrase')

    conn = db.connect(config.db_path)
    try:
        c = db.cursor(conn)
        resp = db.delete_post(c, user_id, session_id, node_name, group_id, owner_id, post_id, passphrase)
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
