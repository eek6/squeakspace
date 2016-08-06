import squeakspace.common.util as ut
import squeakspace.common.util_http as ht
import squeakspace.server.db_sqlite3 as db
import squeakspace.common.squeak_ex as ex
import config

def post_handler(environ):

    query = ht.parse_post_request(environ)

    timestamp = ht.convert_int(ht.get_required(query, 'timestamp'), 'timestamp')
    node_name = ht.get_required(query, 'node_name')
    group_id = ht.get_required(query, 'group_id')
    owner_id = ht.get_required(query, 'owner_id')
    data_hash = ht.get_required(query, 'data_hash')
    post_id = ht.get_required(query, 'post_id')
    data = ht.get_required(query, 'data')
    post_signature = ht.get_optional(query, 'post_signature')
    proof_of_work = ht.get_optional(query, 'proof_of_work')

    conn = db.connect(config.db_path)
    try:
        c = db.cursor(conn)
        row = (post_id, timestamp, group_id, owner_id, data, data_hash, post_signature, proof_of_work, None)
        db.create_post(c, row, node_name)
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
    group_id = ht.get_required(query, 'group_id')
    owner_id = ht.get_required(query, 'owner_id')
    post_id = ht.get_required(query, 'post_id')
    read_signature = ht.get_optional(query, 'read_signature')
    proof_of_work = ht.get_optional(query, 'proof_of_work')

    conn = db.connect(config.db_path)
    try:
        c = db.cursor(conn)
        post = db.read_post(c, timestamp, node_name, group_id, owner_id, post_id, proof_of_work, read_signature)

        raise ht.ok_json({'status' : 'ok', 'post' : post})
        
    except ex.SqueakException as e:
        raise ht.convert_squeak_exception(e)

    finally:
        db.close(conn)


def delete_handler(environ):

    query = ht.parse_post_request(environ)

    timestamp = ht.convert_int(ht.get_required(query, 'timestamp'), 'timestamp')
    node_name = ht.get_required(query, 'node_name')
    group_id = ht.get_required(query, 'group_id')
    owner_id = ht.get_required(query, 'owner_id')
    post_id = ht.get_required(query, 'post_id')
    delete_signature = ht.get_optional(query, 'delete_signature')
    proof_of_work = ht.get_optional(query, 'proof_of_work')

    conn = db.connect(config.db_path)
    try:
        c = db.cursor(conn)
        db.delete_post(c, timestamp, node_name, group_id, owner_id, post_id, proof_of_work, delete_signature)
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
