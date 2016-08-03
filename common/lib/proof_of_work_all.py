

import proof_of_work_dummy
import proof_of_work_hashcash

#dummy = proof_of_work_dummy.ProofOfWorkDummy()   # Only enable dummy proof of work when debugging.
hashcash = proof_of_work_hashcash.ProofOfWorkHashCash()

name_map = {}
# name_map[dummy.name] = dummy
name_map[hashcash.name] = hashcash

alg_map = {}
# alg_map[dummy.standard] = dummy
alg_map[hashcash.standard] = hashcash
