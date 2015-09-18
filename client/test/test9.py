#!/usr/bin/python

import httplib as ht
import json

import client_path
import client as cl
import util as ut
import client_types as tp

import test_params


conn = ht.HTTPConnection(test_params.server_address, test_params.server_port)
client = cl.Client(conn, test_params.node_name)


version = client.read_version()
print version

version = client.read_version()
print version

version = client.read_version()
print version
