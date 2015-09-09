

import squeak_ex as ex

import hashcash

class ProofOfWorkHashCash:
    standard = "hashcash"
    name = "hashcash"

    # parameters:
    #  algorithm: hashcash
    #  bits: required, integer. positive.
    #  salt: optional (8), integer, positive.

    def assert_parameters(self, parameters_obj, parameters, argument):
        bits = parameters_obj.get('bits')
        saltchars = parameters_obj.get('saltchars')

        bits_valid = bits != None and type(bits) == int and bits > 0 and bits < 200
        saltchars_valid = saltchars == None or (type(saltchars) == int and saltchars > 0 and saltchars < 200)

        if (not bits_valid) or (not saltchars_valid):
            raise ex.MalformedProofOfWorkParametersException(parameters, argument)

    def work(self, parameters_obj, data):
        bits = parameters_obj['bits']
        saltchars = parameters_obj.get('saltchars') or 8 # default value from hashcash.py
        return hashcash.mint(data, bits=bits, saltchars=saltchars)

    def verify_proof(self, parameters_obj, data, proof):
        bits = parameters_obj['bits']
        # should the salt be verified?

        return hashcash.check(proof, resource=data, bits=bits)

