#!/usr/bin/python

import httplib as ht

import client_path
import client

import test_params

conn = ht.HTTPConnection(test_params.server_address, test_params.server_port)

cl = client.Client(conn)

print(cl.read_local_version())

print(cl.read_post('john.doe', 'fake_session_id', test_params.node_name, 'group', 'owner', 'post', None))

print(cl.read_local_version())
