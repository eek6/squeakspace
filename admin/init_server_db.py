#!/usr/bin/python2.7
# Run this script as user: www-data

import os
import server_path
import squeakspace.server.db_sqlite3 as db
import config

try:
    os.remove(config.db_path)
except OSError:
    pass

conn = db.connect(config.db_path)
c = db.cursor(conn)
db.make_db(c, config.total_quota)
db.commit(conn)
db.close(conn)
