import config
import crypt_dummy
import crypt_gnupg
import crypt_squeak

import squeak_ex as ex

#dummy = crypt_dummy.CryptDummy() # Only enable the dummy keys when debugging.
gnupg = crypt_gnupg.CryptGnuPG(config.path_root)
squeak = crypt_squeak.CryptSqueak()

name_map = {}
#name_map[dummy.name] = dummy    # Disabled.
name_map[gnupg.name] = gnupg 
name_map[squeak.name] = squeak

alg_map = {}
#alg_map[dummy.standard] = dummy   # Disabled.
alg_map[gnupg.standard] = gnupg
alg_map[squeak.standard] = squeak

def find_alg(key_type):

    alg = alg_map.get(key_type)

    if alg == None:
        raise ex.UnsupportedKeyTypeException(key_type)

    return alg
