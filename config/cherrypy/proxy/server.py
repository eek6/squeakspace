#!/usr/bin/python2.7
# Run this as www-data


import sys
import os.path
import cherrypy

path_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', '..'))
run_ssl = False

sys.path.append(os.path.join(path_root, 'lib'))
sys.path.append(os.path.join(path_root, 'lib', 'gnupg'))
sys.path.append(os.path.join(path_root, 'lib', 'backports.pbkdf2-0.1'))
sys.path.append(os.path.join(path_root, 'config', 'proxy'))
sys.path.append(os.path.join(path_root, 'config', 'common'))
sys.path.append(os.path.join(path_root, 'www', 'proxy'))


import scripts.local.crypt.gen_key
import scripts.local.crypt.encrypt
import scripts.local.crypt.decrypt
import scripts.local.crypt.sign
import scripts.local.crypt.verify_signature

import scripts.local.group_access
import scripts.local.group_key
import scripts.local.list_group_keys
import scripts.local.list_node_addr
import scripts.local.list_other_user_keys
import scripts.local.list_private_keys
import scripts.local.list_public_keys
import scripts.local.list_user_keys
import scripts.local.login
import scripts.local.message_access
import scripts.local.node_addr
import scripts.local.other_user_key
import scripts.local.passphrase
import scripts.local.password
import scripts.local.private_key
import scripts.local.public_key
import scripts.local.sign_out
import scripts.local.user_key
import scripts.local.user
import scripts.local.version

# don't enable this unless debugging.
# If these are enabled, attackers can download the database.
# import scripts.local.debug
# import scripts.proxy.debug

import scripts.proxy.complain
import scripts.proxy.group_access
import scripts.proxy.group_key
import scripts.proxy.group_config
import scripts.proxy.group_quota
import scripts.proxy.group
import scripts.proxy.last_message_time
import scripts.proxy.last_post_time
import scripts.proxy.max_message_size
import scripts.proxy.max_post_size
import scripts.proxy.message_access
import scripts.proxy.message_list
import scripts.proxy.message_quota
import scripts.proxy.message
import scripts.proxy.node
import scripts.proxy.post_list
import scripts.proxy.post
import scripts.proxy.query_message_access
import scripts.proxy.query_user
import scripts.proxy.user_config
import scripts.proxy.user_quota
import scripts.proxy.user
import scripts.proxy.quota_available
import scripts.proxy.version



def start():

    cherrypy.tree.mount(None, '/', {'/': {'tools.staticdir.dir': path_root + '/www/proxy/site',
                                          'tools.staticdir.on': True,
                                          'tools.staticdir.index': 'index.html'}})


    cherrypy.tree.graft(scripts.local.crypt.gen_key.application, '/local/crypt/gen-key')
    cherrypy.tree.graft(scripts.local.crypt.encrypt.application, '/local/crypt/encrypt')
    cherrypy.tree.graft(scripts.local.crypt.decrypt.application, '/local/crypt/decrypt')
    cherrypy.tree.graft(scripts.local.crypt.sign.application, '/local/crypt/sign')
    cherrypy.tree.graft(scripts.local.crypt.verify_signature.application, '/local/crypt/verify-signature')

    cherrypy.tree.graft(scripts.local.group_access.application, '/local/group-access')
    cherrypy.tree.graft(scripts.local.group_key.application, '/local/group-key')
    cherrypy.tree.graft(scripts.local.list_group_keys.application, '/local/list-group-keys')
    cherrypy.tree.graft(scripts.local.list_node_addr.application, '/local/list-node-addr')
    cherrypy.tree.graft(scripts.local.list_other_user_keys.application, '/local/list-other-user-keys')
    cherrypy.tree.graft(scripts.local.list_private_keys.application, '/local/list-private-keys')
    cherrypy.tree.graft(scripts.local.list_public_keys.application, '/local/list-public-keys')
    cherrypy.tree.graft(scripts.local.list_user_keys.application, '/local/list-user-keys')
    cherrypy.tree.graft(scripts.local.login.application, '/local/login')
    cherrypy.tree.graft(scripts.local.message_access.application, '/local/message-access')
    cherrypy.tree.graft(scripts.local.node_addr.application, '/local/node-addr')
    cherrypy.tree.graft(scripts.local.other_user_key.application, '/local/other-user-key')
    cherrypy.tree.graft(scripts.local.passphrase.application, '/local/passphrase')
    cherrypy.tree.graft(scripts.local.password.application, '/local/password')
    cherrypy.tree.graft(scripts.local.private_key.application, '/local/private-key')
    cherrypy.tree.graft(scripts.local.public_key.application, '/local/public-key')
    cherrypy.tree.graft(scripts.local.sign_out.application, '/local/sign-out')
    cherrypy.tree.graft(scripts.local.user_key.application, '/local/user-key')
    cherrypy.tree.graft(scripts.local.user.application, '/local/user')
    cherrypy.tree.graft(scripts.local.version.application, '/local/version')

    # don't enable this unless debugging.
    # If these are enabled, attackers can download the database.
    # cherrypy.tree.graft(scripts.local.debug.application, '/local/debug')
    # cherrypy.tree.graft(scripts.proxy.debug.application, '/proxy/debug')

    cherrypy.tree.graft(scripts.proxy.complain.application, '/proxy/complain')
    cherrypy.tree.graft(scripts.proxy.group_access.application, '/proxy/group-access')
    cherrypy.tree.graft(scripts.proxy.group_key.application, '/proxy/group-key')
    cherrypy.tree.graft(scripts.proxy.group_config.application, '/proxy/group-config')
    cherrypy.tree.graft(scripts.proxy.group_quota.application, '/proxy/group-quota')
    cherrypy.tree.graft(scripts.proxy.group.application, '/proxy/group')
    cherrypy.tree.graft(scripts.proxy.last_message_time.application, '/proxy/last-message-time')
    cherrypy.tree.graft(scripts.proxy.last_post_time.application, '/proxy/last-post-time')
    cherrypy.tree.graft(scripts.proxy.max_message_size.application, '/proxy/max-message-size')
    cherrypy.tree.graft(scripts.proxy.max_post_size.application, '/proxy/max-post-size')
    cherrypy.tree.graft(scripts.proxy.message_access.application, '/proxy/message-access')
    cherrypy.tree.graft(scripts.proxy.message_list.application, '/proxy/message-list')
    cherrypy.tree.graft(scripts.proxy.message_quota.application, '/proxy/message-quota')
    cherrypy.tree.graft(scripts.proxy.message.application, '/proxy/message')
    cherrypy.tree.graft(scripts.proxy.node.application, '/proxy/node')
    cherrypy.tree.graft(scripts.proxy.post_list.application, '/proxy/post-list')
    cherrypy.tree.graft(scripts.proxy.post.application, '/proxy/post')
    cherrypy.tree.graft(scripts.proxy.query_message_access.application, '/proxy/query-message-access')
    cherrypy.tree.graft(scripts.proxy.query_user.application, '/proxy/query-user')
    cherrypy.tree.graft(scripts.proxy.user_config.application, '/proxy/user-config')
    cherrypy.tree.graft(scripts.proxy.user_quota.application, '/proxy/user-quota')
    cherrypy.tree.graft(scripts.proxy.user.application, '/proxy/user')
    cherrypy.tree.graft(scripts.proxy.quota_available.application, '/proxy/quota-available')
    cherrypy.tree.graft(scripts.proxy.version.application, '/proxy/version')


    cherrypy.server.unsubscribe()

    server_plain = cherrypy._cpserver.Server()
    server_plain.socket_host = '127.0.0.1'
    server_plain.socket_port = 12323
    server_plain.thread_pool = 15
    server_plain.subscribe()


    if run_ssl == True:
        server_ssl = cherrypy._cpserver.Server()
        server_ssl.socket_host = '127.0.0.1'
        server_ssl.socket_port = 12324
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
