#!/usr/bin/python


import server_path
import db_sqlite3 as db
import config

conn = db.connect(config.db_path)
c = db.cursor(conn)
db.make_db(c, config.total_quota)
db.commit(conn)
db.close(conn)
