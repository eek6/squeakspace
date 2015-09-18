

import os
import base64
import config_proto

# bytes isn't literal length of the token
def gen_session_id(bytes):
    data = os.urandom(bytes)
    return base64.b64encode(data)

