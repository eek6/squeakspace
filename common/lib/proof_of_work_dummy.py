

import squeak_ex as ex

class ProofOfWorkDummy:
    standard = "dummy"
    name = "dummy"

    def assert_parameters(self, parameters_obj, parameters, argument):
        try:
            level = parameters_obj['level']
        except KeyError:
            raise ex.MalformedProofOfWorkParametersException(parameters, argument)

    def work(self, parameters_obj, data):
        level = parameters_obj['level']
        return 'proof_of_work;' + str(level) + ';' + data

    def verify_proof(self, parameters_obj, data, proof):
        level = parameters_obj['level']
        try:
            (start, lev, dat) = proof.split(';')
            return start == 'proof_of_work' and \
                   int(lev) == level and \
                   dat == data
        except:
            return False


