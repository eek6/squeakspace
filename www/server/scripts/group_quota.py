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
    new_size = ht.convert_int(ht.get_required(query, 'new_size'), 'new_size')
    when_space_exhausted = ht.get_required(query, 'when_space_exhausted')

    public_key_hash = ht.get_required(query, 'public_key_hash')
    signature = ht.get_required(query, 'signature')

    conn = db.connect(config.db_path)
    try:
        c = db.cursor(conn)
        db.change_group_quota(c,
                timestamp, node_name, group_id, owner_id,
                new_size, when_space_exhausted,
                public_key_hash, signature)
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
    read_signature = ht.get_optional(query, 'read_signature')
    proof_of_work = ht.get_optional(query, 'proof_of_work')

    conn = db.connect(config.db_path)
    try:
        c = db.cursor(conn)
        group_quota = db.read_group_quota(c,
                timestamp, node_name, group_id, owner_id,
                read_signature, proof_of_work)

        raise ht.ok_json({'status' : 'ok', 'group_quota' : group_quota})

    except ex.SqueakException as e:
        raise ht.convert_squeak_exception(e)

    finally:
        db.close(conn)


def main_handler(environ):
    ht.dispatch_on_method(environ, {
            'POST' : post_handler,
            'GET' : get_handler})

def application(environ, start_response):
    return ht.respond_with_handler(environ, start_response, main_handler)
