import squeakspace.common.util as ut
import squeakspace.common.util_http as ht
import squeakspace.server.db_sqlite3 as db
import squeakspace.common.squeak_ex as ex
import config

def get_handler(environ):

    query = ht.parse_get_request(environ)

    timestamp = ht.convert_int(ht.get_required(query, 'timestamp'), 'timestamp')
    node_name = ht.get_required(query, 'node_name')
    group_id = ht.get_required(query, 'group_id')
    owner_id = ht.get_required(query, 'owner_id')
    start_time = ht.convert_int(ht.get_optional(query, 'start_time'), 'start_time')
    end_time = ht.convert_int(ht.get_optional(query, 'end_time'), 'end_time')
    max_records = ht.convert_int(ht.get_optional(query, 'max_records'), 'max_records')
    order = ht.get_optional(query, 'order')
    read_signature = ht.get_optional(query, 'read_signature')
    proof_of_work = ht.get_optional(query, 'proof_of_work')

    conn = db.connect(config.db_path)
    try:
        c = db.cursor(conn)
        post_list = db.read_post_list(
                c, timestamp, node_name, group_id, owner_id,
                start_time, end_time, max_records,
                order, read_signature, proof_of_work)

        raise ht.ok_json({'status' : 'ok', 'post_list' : post_list})

    except ex.SqueakException as e:
        raise ht.convert_squeak_exception(e)

    finally:
        db.close(conn)

def main_handler(environ):
    ht.dispatch_on_method(environ, {'GET' : get_handler})

def application(environ, start_response):
    return ht.respond_with_handler(environ, start_response, main_handler)
