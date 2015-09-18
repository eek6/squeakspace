
import json

server_address = 'localhost'
server_port = 12323

node_name = 'node_name'
node_addr = 'http://localhost:80'

key_type = 'dummy'
#key_type = 'pgp'
key_params = json.dumps({})


#proof_of_work_args = json.dumps({'algorithm':'dummy','level':2})
#bad_proof_of_work_args = json.dumps({'algorithm':'dummy','level':1})
#proof_of_work_args = json.dumps({'algorithm':'hashcash','bits':20})
#bad_proof_of_work_args = json.dumps({'algorithm':'hashcash','bits':18})
proof_of_work_args = json.dumps({'algorithm':'hashcash','bits':14})
bad_proof_of_work_args = json.dumps({'algorithm':'hashcash','bits':12})



