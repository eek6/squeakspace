#!/usr/bin/python

import httplib as ht

import client_path
import client as cl
import client_raw as raw

import test_params

conn = ht.HTTPConnection(test_params.server_address, test_params.server_port)

print(raw.send_and_get(conn, 'GET', 'root', 'foo=bar'))
