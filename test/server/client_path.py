import sys
import os.path

squeakspace_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))

sys.path.append(os.path.join(squeakspace_root, 'lib'))
sys.path.append(os.path.join(squeakspace_root, 'lib', 'gnupg'))
