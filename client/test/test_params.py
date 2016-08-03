
import json

server_address = 'localhost'
server_port = 80
node_name = 'node_name'
node_debug_enabled = False

#key_type = 'dummy'
#key_type = 'pgp'
key_type = 'squeak'

#proof_of_work_args = json.dumps({'algorithm':'dummy','level':2})
#bad_proof_of_work_args = json.dumps({'algorithm':'dummy','level':1})
#proof_of_work_args = json.dumps({'algorithm':'hashcash','bits':20})
#bad_proof_of_work_args = json.dumps({'algorithm':'hashcash','bits':18})
proof_of_work_args = json.dumps({'algorithm':'hashcash','bits':14})
bad_proof_of_work_args = json.dumps({'algorithm':'hashcash','bits':12})
