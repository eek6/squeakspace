import util as ut
import util_http as ht
import db_sqlite3 as db
import squeak_ex as ex
import config


def post_handler(environ):

    query = ht.parse_post_request(environ)

    timestamp = ht.convert_int(ht.get_required(query, 'timestamp'), 'timestamp')
    node_name = ht.get_required(query, 'node_name')
    group_id = ht.get_required(query, 'group_id')
    owner_id = ht.get_required(query, 'owner_id')
    use = ht.get_required(query, 'use')
    access = ht.get_required(query, 'access')
    public_key_hash = ht.get_required(query, 'public_key_hash')
    signature = ht.get_required(query, 'signature')

    conn = db.connect(config.db_path)
    try:
        c = db.cursor(conn)
        db.change_group_access(c, timestamp, node_name, group_id, owner_id, use, access,
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
    use = ht.get_required(query, 'use')
    signature = ht.get_optional(query, 'signature')

    conn = db.connect(config.db_path)
    try:
        c = db.cursor(conn)
        access = db.read_group_access(c, timestamp, node_name, group_id, owner_id, use, signature)

        raise ht.ok_json({'status' : 'ok', 'access' : access})

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
