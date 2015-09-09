#!/usr/bin/python

import httplib as ht

import client_path
import client as cl

import test_params

conn = ht.HTTPConnection(test_params.server_address, test_params.server_port)
client = cl.Client(conn, test_params.node_name)

print(client.read_post('group', 'owner', 'post', None, None))

print(client.read_version())
