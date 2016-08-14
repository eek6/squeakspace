#!/usr/bin/python2.7
# Run this as www-data
#
# This is the cherrypy configuration for a squeakspace node.
# I recommend you use apache instead, since it will face
# the outside internet.

import sys
import os.path
import cherrypy

path_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', '..'))
run_ssl = True

sys.path.append(os.path.join(path_root, 'lib'))
sys.path.append(os.path.join(path_root, 'lib', 'gnupg'))
sys.path.append(os.path.join(path_root, 'config', 'server'))
sys.path.append(os.path.join(path_root, 'config', 'common'))
sys.path.append(os.path.join(path_root, 'www', 'server'))



import scripts.complain
import scripts.group_access
import scripts.group_config
import scripts.group_key
import scripts.group_quota
import scripts.group
import scripts.last_message_time
import scripts.last_post_time
import scripts.query_message_access
import scripts.query_user
import scripts.max_message_size
import scripts.max_post_size
import scripts.message_access
import scripts.message_list
import scripts.message_quota
import scripts.message
import scripts.node
import scripts.post_list
import scripts.post
import scripts.user_config
import scripts.user_quota
import scripts.quota_available
import scripts.user
import scripts.version

# Below are for debugging. Don't enable in the wild.
# If enabled, anyone can download the database.
# import scripts.debug


def start():

    cherrypy.tree.mount(None, '/', {'/': {'tools.staticdir.dir': path_root + '/www/server/site',
                                          'tools.staticdir.on': True,
                                          'tools.staticdir.index': 'index.html'}})


    cherrypy.tree.graft(scripts.complain.application, '/complain')
    cherrypy.tree.graft(scripts.group_access.application, '/group-access')
    cherrypy.tree.graft(scripts.group_config.application, '/group-config')
    cherrypy.tree.graft(scripts.group_key.application, '/group-key')
    cherrypy.tree.graft(scripts.group_quota.application, '/group-quota')
    cherrypy.tree.graft(scripts.group.application, '/group')
    cherrypy.tree.graft(scripts.last_message_time.application, '/last-message-time')
    cherrypy.tree.graft(scripts.last_post_time.application, '/last-post-time')
    cherrypy.tree.graft(scripts.query_message_access.application, '/query-message-access')
    cherrypy.tree.graft(scripts.query_user.application, '/query-user')
    cherrypy.tree.graft(scripts.max_message_size.application, '/max-message-size')
    cherrypy.tree.graft(scripts.max_post_size.application, '/max-post-size')
    cherrypy.tree.graft(scripts.message_access.application, '/message-access')
    cherrypy.tree.graft(scripts.message_list.application, '/message-list')
    cherrypy.tree.graft(scripts.message_quota.application, '/message-quota')
    cherrypy.tree.graft(scripts.message.application, '/message')
    cherrypy.tree.graft(scripts.node.application, '/node')
    cherrypy.tree.graft(scripts.post_list.application, '/post-list')
    cherrypy.tree.graft(scripts.post.application, '/post')
    cherrypy.tree.graft(scripts.user_config.application, '/user-config')
    cherrypy.tree.graft(scripts.user_quota.application, '/user-quota')
    cherrypy.tree.graft(scripts.quota_available.application, '/quota-available')
    cherrypy.tree.graft(scripts.user.application, '/user')
    cherrypy.tree.graft(scripts.version.application, '/version')

    # Below are for debugging. Don't enable in the wild.
    # If enabled, anyone can download the database.
    # cherrypy.tree.graft(scripts.debug.application, '/debug')


    cherrypy.server.unsubscribe()

    server_plain = cherrypy._cpserver.Server()
    server_plain.socket_host = '0.0.0.0'
    server_plain.socket_port = 12325
    server_plain.thread_pool = 15
    server_plain.subscribe()


    if run_ssl == True:
        server_ssl = cherrypy._cpserver.Server()
        server_ssl.socket_host = '0.0.0.0'
        server_ssl.socket_port = 12326
        server_ssl.thread_pool = 15

        server_ssl.ssl_module = 'pyopenssl'
        server_ssl.ssl_certificate = os.path.join(path_root, 'config', 'ssl', 'selfcert.crt')
        server_ssl.ssl_private_key = os.path.join(path_root, 'config', 'ssl', 'key.pem')
        server_ssl.ssl_certificate_chain = None
        server_ssl.subscribe()

    cherrypy.engine.start()
    cherrypy.engine.block()


if __name__ == '__main__':
    start()

