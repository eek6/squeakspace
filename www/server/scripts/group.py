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
    post_access = ht.get_required(query, 'post_access')
    read_access = ht.get_required(query, 'read_access')
    delete_access = ht.get_required(query, 'delete_access')
    posting_key_type = ht.get_optional(query, 'posting_key_type')
    posting_pub_key = ht.get_optional(query, 'posting_pub_key')
    reading_key_type = ht.get_optional(query, 'reading_key_type')
    reading_pub_key = ht.get_optional(query, 'reading_pub_key')
    delete_key_type = ht.get_optional(query, 'delete_key_type')
    delete_pub_key = ht.get_optional(query, 'delete_pub_key')
    quota_allocated = ht.convert_int(ht.get_required(query, 'quota_allocated'), 'quota_allocated')
    when_space_exhausted = ht.get_required(query, 'when_space_exhausted')
    max_post_size = ht.convert_int(ht.get_optional(query, 'max_post_size'), 'max_post_size')

    public_key_hash = ht.get_required(query, 'public_key_hash')
    signature = ht.get_required(query, 'signature')

    conn = db.connect(config.db_path)
    try:
        c = db.cursor(conn)
        row = (timestamp, group_id, owner_id,
               post_access, read_access, delete_access,
               posting_key_type, posting_pub_key,
               reading_key_type, reading_pub_key,
               delete_key_type, delete_pub_key,
               quota_allocated, when_space_exhausted,
               max_post_size)
        db.create_group(c, row, node_name, public_key_hash, signature)
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
    public_key_hash = ht.get_required(query, 'public_key_hash')
    signature = ht.get_required(query, 'signature')

    conn = db.connect(config.db_path)
    try:
        c = db.cursor(conn)
        group = db.read_group(c, timestamp, node_name, group_id, owner_id, public_key_hash, signature)

        raise ht.ok_json({'status' : 'ok', 'group' : group})

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

    public_key_hash = ht.get_required(query, 'public_key_hash')
    signature = ht.get_required(query, 'signature')

    conn = db.connect(config.db_path)
    try:
        c = db.cursor(conn)
        group = db.delete_group(c, timestamp, node_name, group_id, owner_id, public_key_hash, signature)
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
