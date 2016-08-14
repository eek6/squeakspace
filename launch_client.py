#!/usr/bin/python2.7


import httplib as http
import webbrowser as web
import os
import sys

path_root = os.path.abspath(os.path.dirname(__file__))

sys.path.append(os.path.join(path_root, 'config', 'cherrypy', 'proxy'))
import server

server_started = True

test_conn = http.HTTPConnection('localhost', 12323)
try:
    test_conn.connect()
    test_conn.close()

except IOError as e:
    server_started = False


web.open('http://localhost:12323')
if server_started == False:
    # server.start() blocks, so do it last.
    server.start()

