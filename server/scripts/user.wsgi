import json
import util as ut
import util_http as ht
import config
import squeak_ex as ex
import db_sqlite3 as db



def post_handler(environ):

    query = ht.parse_post_request(environ)

    node_name = ht.get_required(query, 'node_name')
    user_id = ht.get_required(query, 'user_id')
    key_type = ht.get_required(query, 'key_type')
    public_key = ht.get_required(query, 'public_key')
    public_key_hash = ht.get_required(query, 'public_key_hash')
    revoke_date = ht.convert_int(ht.get_optional(query, 'revoke_date'), 'revoke_date')
    default_message_access = ht.get_required(query, 'default_message_access')
    when_mail_exhausted = ht.get_required(query, 'when_mail_exhausted')
    quota_size = ht.convert_int(ht.get_required(query, 'quota_size'), 'quota_size')
    mail_quota_size = ht.convert_int(ht.get_required(query, 'mail_quota_size'), 'mail_quota_size')
    max_message_size = ht.convert_int(ht.get_optional(query, 'max_message_size'), 'max_message_size')

    # TODO: figure these out
    user_class = ht.get_optional(query, 'user_class')
    auth_token = ht.get_optional(query, 'auth_token')

    conn = db.connect(config.db_path)
    try:
        c = db.cursor(conn)
        db.create_user(c, node_name,
                       user_id, key_type, public_key, public_key_hash, revoke_date,
                       default_message_access, when_mail_exhausted,
                       db.root_quota_id, quota_size, mail_quota_size,
                       max_message_size)
        db.commit(conn)

        raise ht.ok_json({'status' : 'ok'})

    except ex.SqueakException as e:
        raise ht.convert_squeak_exception(e)

    finally:
        db.close(conn)


def get_handler(environ):

    query = ht.parse_get_request(environ)

    timestamp = ht.convert_int(ht.get_required(query, 'timestamp'), 'timestamp')
    node_name = ht.get_required(query, 'node_name')
    user_id = ht.get_required(query, 'user_id')
    public_key_hash = ht.get_required(query, 'public_key_hash')
    signature = ht.get_required(query, 'signature')

    conn = db.connect(config.db_path)
    try:
        c = db.cursor(conn)
        user_obj = db.read_user(c, timestamp, node_name, user_id, public_key_hash, signature)

        raise ht.ok_json({'status' : 'ok', 'user' : user_obj})

    except ex.SqueakException as e:
        raise ht.convert_squeak_exception(e)

    finally:
        db.close(conn)


def delete_handler(environ):

    query = ht.parse_post_request(environ)

    timestamp = ht.convert_int(ht.get_required(query, 'timestamp'), 'timestamp')
    node_name = ht.get_required(query, 'node_name')
    user_id = ht.get_required(query, 'user_id')
    public_key_hash = ht.get_required(query, 'public_key_hash')
    signature = ht.get_required(query, 'signature')

    conn = db.connect(config.db_path)
    try:
        c = db.cursor(conn)
        c2 = db.cursor(conn)
        db.delete_user(c, c2, timestamp, node_name, user_id, public_key_hash, signature)
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

