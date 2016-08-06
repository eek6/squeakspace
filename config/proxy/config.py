

import os.path

squeakspace_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))

path_root = os.path.join(squeakspace_root, 'www', 'data', 'proxy')

session_id_len = 33

# sessions expire after session_expire_time milliseconds
session_expire_delay = 30*60*1000 # 30 minutes

db_path = os.path.join(squeakspace_root, 'www', 'data', 'database', 'proxy.db')

pass_hash_fun = 'sha1'
pass_rounds = 1000
pass_salt_len = 16
