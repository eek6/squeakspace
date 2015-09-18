#!/usr/bin/python

import sys

sys.path.append('../../common/lib')

import httplib as ht
import client_path
import client as cl
import client_raw as raw
import util_client as uc

send_and_getter = uc.SendAndGetter()


import test_params

conn = ht.HTTPConnection(test_params.server_address, test_params.server_port)

print(send_and_getter.send_and_get(conn, 'GET', 'root', 'foo=bar'))
