
# path_root defined here is used by crypt_gnupg

import os.path

squeakspace_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))

path_root = os.path.join(squeakspace_root, 'test', 'data', 'server')

