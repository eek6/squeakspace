#!/usr/bin/python
# Run this script as user: www-data

import proxy_path
import squeakspace.proxy.server.db_sqlite3 as db
import config
import os

try:
    os.remove(config.db_path)
except OSError:
    pass
        
conn = db.connect(config.db_path)
c = db.cursor(conn)
db.make_db(c)
db.commit(conn)
db.close(conn)
