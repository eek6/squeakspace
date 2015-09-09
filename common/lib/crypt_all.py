import config
import crypt_dummy
import crypt_gnupg

import squeak_ex as ex

dummy = crypt_dummy.CryptDummy()
gnupg = crypt_gnupg.CryptGnuPG(config.path_root)

name_map = {}
name_map[dummy.name] = dummy
name_map[gnupg.name] = gnupg 

alg_map = {}
alg_map[dummy.standard] = dummy
alg_map[gnupg.standard] = gnupg

def find_alg(key_type):

    alg = alg_map.get(key_type)

    if alg == None:
        raise ex.UnsupportedKeyTypeException(key_type)

    return alg
