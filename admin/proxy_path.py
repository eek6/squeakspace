import sys
import os.path

squeakspace_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))

sys.path.append(os.path.join(squeakspace_root, 'lib'))
sys.path.append(os.path.join(squeakspace_root, 'lib', 'gnupg'))
sys.path.append(os.path.join(squeakspace_root, 'lib', 'backports.pbkdf2-0.1'))
sys.path.append(os.path.join(squeakspace_root, 'config', 'proxy'))
sys.path.append(os.path.join(squeakspace_root, 'config', 'common'))
