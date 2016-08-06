
# DON'T ENABLE IF FACING THE INTERNET
# This script exposes debug routines
# to the client.

import squeakspace.common.util as ut
import squeakspace.common.util_http as ht
import squeakspace.common.squeak_ex as ex
import squeakspace.server.db_sqlite3 as db
import config

def get_handler(environ):

    query = ht.parse_get_request(environ)

    action = ht.get_required(query, 'action')

    conn = db.connect(config.db_path)
    try:
        res = None

        if action == 'database':
            c = db.cursor(conn)
            res = db.read_database(c)
        elif action == 'integrity':
            all_local = ht.convert_bool(ht.get_required(query, 'all_local'), 'all_local')
            c1 = db.cursor(conn)
            c2 = db.cursor(conn)
            res = db.check_integrity(c1, c2, all_local)
        else:
            raise ht.BadFieldResponse('action', action)

        raise ht.ok_json({'status' : 'ok', 'res' : res})

    except ex.SqueakException as e:
        raise ht.convert_squeak_exception(e)

    finally:
        db.close(conn)

def main_handler(environ):
    ht.dispatch_on_method(environ, {'GET' : get_handler})

def application(environ, start_response):
    return ht.respond_with_handler(environ, start_response, main_handler)
