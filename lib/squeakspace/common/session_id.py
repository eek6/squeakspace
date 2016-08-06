

import os
import base64
import config_proto

def gen_session_id(bytes):
    data = os.urandom(bytes)
    return base64.urlsafe_b64encode(data)
