
import os.path

_kb = 1024
_mb = 1024*_kb
_gb = 1024*_mb

squeakspace_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))

node_name = "node_name"

db_path = os.path.join(squeakspace_root, 'www', 'data', 'database', 'server.db')
init_trust_score = 0
total_quota = 2*_gb 

# used by gpg
path_root = os.path.join(squeakspace_root, 'www', 'data', 'server')

# seconds
acceptable_future = -1*1000
acceptable_delay = 180*1000

max_user_quota = 200*_mb
