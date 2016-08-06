import squeakspace.common.util as ut
import squeakspace.common.util_http as ht
import squeakspace.server.db_sqlite3 as db
import squeakspace.common.squeak_ex as ex
import config

def get_handler(environ):

    query = ht.parse_get_request(environ)

    timestamp = ht.convert_int(ht.get_required(query, 'timestamp'), 'timestamp')
    node_name = ht.get_required(query, 'node_name')
    user_id = ht.get_required(query, 'user_id')
    to_user_key = ht.get_optional(query, 'to_user_key')
    from_user = ht.get_optional(query, 'from_user')
    from_user_key = ht.get_optional(query, 'from_user_key')
    start_time = ht.convert_int(ht.get_optional(query, 'start_time'), 'start_time')
    end_time = ht.convert_int(ht.get_optional(query, 'end_time'), 'end_time')
    max_records = ht.convert_int(ht.get_optional(query, 'max_records'), 'max_records')
    order = ht.get_optional(query, 'order')
    public_key_hash = ht.get_required(query, 'public_key_hash')
    signature = ht.get_required(query, 'signature')

    conn = db.connect(config.db_path)
    try:
        c = db.cursor(conn)
        message_list = db.read_message_list(c, timestamp, node_name, user_id,
                                            to_user_key, from_user, from_user_key,
                                            start_time, end_time, max_records, order,
                                            public_key_hash, signature)

        raise ht.ok_json({'status' : 'ok', 'message_list' : message_list})

    except ex.SqueakException as e:
        raise ht.convert_squeak_exception(e)

    finally:
        db.close(conn)



def main_handler(environ):
    ht.dispatch_on_method(environ, {'GET' : get_handler})

def application(environ, start_response):
    return ht.respond_with_handler(environ, start_response, main_handler)

