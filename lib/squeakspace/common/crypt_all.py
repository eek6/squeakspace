import config
import squeakspace.common.crypt_dummy as crypt_dummy
import squeakspace.common.crypt_gnupg as crypt_gnupg
import squeakspace.common.crypt_squeak as crypt_squeak

import squeak_ex as ex

#dummy = crypt_dummy.CryptDummy() # Only enable the dummy keys when debugging.
#gnupg = crypt_gnupg.CryptGnuPG(config.path_root) # Disabled to make installation easier.
squeak = crypt_squeak.CryptSqueak()

name_map = {}
#name_map[dummy.name] = dummy    # Disabled.
#name_map[gnupg.name] = gnupg 
name_map[squeak.name] = squeak

alg_map = {}
#alg_map[dummy.standard] = dummy   # Disabled.
#alg_map[gnupg.standard] = gnupg
alg_map[squeak.standard] = squeak

def find_alg(key_type):

    alg = alg_map.get(key_type)

    if alg == None:
        raise ex.UnsupportedKeyTypeException(key_type)

    return alg
