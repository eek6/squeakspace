// squeakclient-0.0.0.js
//

(function() {

var request = function(request_def) {
    var url = request_def.url,
        method = request_def.method,
        cache = request_def.cache || false;

    return function(data, complete, settings) {
        var s = settings || {},
            c = complete || function(resp, textStatus) {},
            ajaxComplete = function(jqXHR, textStatus) {
                //var resp = jqXHR.responseXML;
                //var resp = jqXHR.responseText;
                var resp = JSON.parse(jqXHR.responseText);
                return c(resp, textStatus);
            };
        s.url = url;
        s.method = method;
        s.cache = cache;
        s.dataType = 'json';
        s.data = data;
        s.complete = ajaxComplete;

        $.ajax(s);
    };
};


squeakclient = {};

squeakclient.local = {};

squeakclient.local.crypt = {};

//
// local/crypt/encrypt.wsgi
//

squeakclient.local.crypt.encrypt = request({url: '/local/crypt/encrypt', method: 'POST'});
// public_key_hash, plaintext


//
// local/crypt/decrypt.wsgi
//

squeakclient.local.crypt.decrypt = request({url: '/local/crypt/decrypt', method: 'POST'});
// public_key_hash, ciphertext, passphrase


//
// local/crypt/verify_signature.wsgi
//

squeakclient.local.crypt.verify_signature = request({url: '/local/crypt/verify-signature', method: 'POST'});
// public_key_hash, data, signature


//
// local/crypt/sign.wsgi
//

squeakclient.local.crypt.sign = request({url: '/local/crypt/sign', method: 'POST'});
// public_key_hash, data, passphrase

//
// local/public-key.wsgi
//

squeakclient.local.read_public_key = request({url: '/local/public-key', method: 'GET'});
// public_key_hash

squeakclient.local.delete_public_key = request({url: '/local/public-key', method: 'DELETE'});
// public_key_hash

squeakclient.local.import_public_key = request({url: '/local/public-key', method: 'POST'});
// key_type, public_key, revoke_date


//
// local/private-key.wsgi
//

squeakclient.local.read_private_key = request({url: '/local/private-key', method: 'GET'});
// public_key_hash, only_public_part?, allow_private_user_key?

squeakclient.local.delete_private_key = request({url: '/local/private-key', method: 'DELETE'});
// public_key_hash

squeakclient.local.import_private_key = request({url: '/local/private-key', method: 'POST'});
// key_type, public_key, private_key, revoke_date


//
// local/crypt/gen-key.wsgi
//

squeakclient.local.generate_private_key = request({url: '/local/crypt/gen-key', method: 'POST'});
// key_type, key_parameters, revoke_date, passphrase


//
// local/group-key.wsgi
//

squeakclient.local.read_group_key = request({url: '/local/group-key', method: 'POST'});
// group_id, owner_id, node_name, key_use

squeakclient.local.delete_group_key = request({url: '/local/group-key', method: 'DELETE'});
// group_id, owner_id, node_name, key_use

squeakclient.local.assign_group_key = request({url: '/local/group-key', method: 'POST'});
// group_id, owner_id, node_name, key_use, public_key_hash


//
// local/list-public-keys.wsgi
//

squeakclient.local.list_public_keys = request({url: '/local/list-public-keys', method: 'GET'});

//
// local/list-private-keys.wsgi
//

squeakclient.local.list_private_keys = request({url: '/local/list-private-keys', method: 'GET'});

//
// local/list-user-keys.wsgi
//

squeakclient.local.list_user_keys = request({url: '/local/list-user-keys', method: 'GET'});
// node_name -- optional

//
// local/list-group-keys.wsgi
//

squeakclient.local.list_group_keys = request({url: '/local/list-group-keys', method: 'GET'});

//
// local/list-other-user-keys.wsgi
//

squeakclient.local.list_other_user_keys = request({url: '/local/list-other-user-keys', method: 'GET'});
// other_user_id?, node_name?

//
// local/user-key.wsgi
//

squeakclient.local.read_user_key = request({url: '/local/user-key', method: 'GET'});
// node_name?, public_key_hash

squeakclient.local.delete_user_key = request({url: '/local/user-key', method: 'DELETE'});
// node_name?, public_key_hash

squeakclient.local.assign_user_key = request({url: '/local/user-key', method: 'POST'});
// node_name?, public_key_hash

//
// local/other-user-key.wsgi
//

squeakclient.local.read_other_user_key = request({url: '/local/other-user-key', method: 'GET'});
// other_user_id, node_name, public_key_hash

squeakclient.local.delete_other_user_key = request({url: '/local/other-user-key', method: 'DELETE'});
// other_user_id, node_name, public_key_hash

squeakclient.local.assign_other_user_key = request({url: '/local/other-user-key', method: 'POST'});
// other_user_id, node_name, public_key_hash, trust_score


//
// local/node-addr.wsgi
//

squeakclient.local.read_node_addr = request({url: '/local/node-addr', method: 'GET'});
// node_name


squeakclient.local.set_node_addr = request({url: '/local/node-addr', method: 'POST'});
// node_name, url, real_node_name


squeakclient.local.delete_node_addr = request({url: '/local/node-addr', method: 'DELETE'});
// node_name


//
// local/list-node-addr.wsgi
//

squeakclient.local.list_node_addr = request({url: '/local/list-node-addr', method: 'GET'});

//
// local/group-access.wsgi
//

squeakclient.local.read_group_access = request({url: '/local/group-access', method: 'GET'});
// group_id, owner_id, node_name, use


squeakclient.local.set_group_access = request({url: '/local/group-access', method: 'POST'});
// group_id, owner_id, node_name, use, access, timestamp


squeakclient.local.delete_group_access = request({url: '/local/group-access', method: 'DELETE'});
// group_id, owner_id, node_name, use

//
// local/message-access.wsgi
//

squeakclient.local.read_message_access = request({url: '/local/message-access', method: 'GET'});
// to_user, node_name, from_user_key_hash


squeakclient.local.set_message_access = request({url: '/local/message-access', method: 'POST'});
// to_user, node_name, from_user_key_hash, access, timestamp


squeakclient.local.delete_message_access = request({url: '/local/message-access', method: 'DELETE'});
// to_user, node_name, from_user_key_hash


//
// local/passphrase.wsgi
//

squeakclient.local.cache_passphrase = request({url: '/local/passphrase', method: 'POST'});
// public_key_hash
// passphrase
// expire_time -- or null

squeakclient.local.delete_passphrase = request({url: '/local/passphrase', method: 'DELETE'});
// public_key_hash -- or null


//
// local/password.wsgi
//

squeakclient.local.set_password = request({url: '/local/password', method: 'POST'});
// method -- hash or passphrase
// password -- present if method == hash
// public_key_hash -- present if method == passphrase


squeakclient.local.read_password = request({url: '/local/password', method: 'GET'});

//
// local/login.wsgi
//

squeakclient.local.login = request({url: '/local/login', method: 'POST'});
// user_id, password


//
// local/sign-out.wsgi
//

squeakclient.local.sign_out = request({url: '/local/sign-out', method: 'GET'});

//
// local/user.wsgi
//

squeakclient.local.create_user = request({url: '/local/user', method: 'POST'});
// user_id, password

squeakclient.local.delete_user = request({url: '/local/user', method: 'DELETE'});


//
// local/version.wsgi
//

squeakclient.local.read_version = request({url: '/local/version', method: 'GET'});


//
// proxy/complain.wsgi
//

//
// proxy/group-access.wsgi
//

squeakclient.proxy = {};

squeakclient.proxy.set_group_access = request({url: '/proxy/group-access', method: 'POST'});
// node_name, group_id, use, access, public_key_hash, passphrase

squeakclient.proxy.read_group_access = request({url: '/proxy/group-access', method: 'GET'});
// node_name, group_id, owner_id, use, passphrase
 
//
// proxy/group-key.wsgi
//

squeakclient.proxy.set_group_key = request({url: '/proxy/group-key', method: 'POST'});
// node_name, group_id, key_use, group_key_hash, public_key_hash, passphrase

squeakclient.proxy.read_group_key = request({url: '/proxy/group-key', method: 'GET'});
// node_name, group_id, key_use, public_key_hash, passphrase


//
// proxy/group-config.wsgi
//

//
// proxy/group-quota.wsgi
//

squeakclient.proxy.change_group_quota = request({url: '/proxy/group-quota', method: 'POST'});
// node_name, group_id, new_size, when_space_exhausted, public_key_hash, passphrase

squeakclient.proxy.read_group_quota = request({url: '/proxy/group-quota', method: 'GET'});
// node_name, group_id, owner_id, passphrase

//
// proxy/group.wsgi
//

squeakclient.proxy.create_group = request({url: '/proxy/group', method: 'POST'});
// node_name, group_id,
// post_access, read_access, delete_access,
// posting_key_hash, reading_key_hash, delete_key_hash,
// quota_allocated, when_space_exhausted, max_post_size,
// public_key_hash, passphrase

squeakclient.proxy.read_group = request({url: '/proxy/group', method: 'GET'});
// node_name, group_id, public_key_hash, passphrase 

squeakclient.proxy.delete_group = request({url: '/proxy/group', method: 'DELETE'});
// node_name, group_id, public_key_hash, passphrase 


//
// proxy/last-message-time.wsgi
//

squeakclient.proxy.read_last_message_time = request({url: '/proxy/last-message-time', method: 'GET'});
// node_name, public_key_hash, passphrase

//
// proxy/last-post-time.wsgi
//

squeakclient.proxy.read_last_post_time = request({url: '/proxy/last-post-time', method: 'GET'});
// node_name, group_id, owner_id, passphrase

//
// proxy/query-message-access.wsgi
//

squeakclient.proxy.query_message_access = request({url: '/proxy/query-message-access', method: 'POST'});
// node_name, to_user, from_user_key_hash, passphrase


//
// proxy/max-message-size.wsgi
//

squeakclient.proxy.read_max_message_size = request({url: '/proxy/max-message-size', method: 'GET'});
// node_name, to_user, from_user_key_hash, passphrase

squeakclient.proxy.change_max_message_size = request({url: '/proxy/max-message-size', method: 'POST'});
// node_name, new_size, public_key_hash, passphrase


//
// proxy/max-post-size.wsgi
//


squeakclient.proxy.read_max_post_size = request({url: '/proxy/max-post-size', method: 'GET'});
// node_name, group_id, owner_id, passphrase

squeakclient.proxy.change_max_post_size = request({url: '/proxy/max-post-size', method: 'POST'});
// node_name, group_id, new_size, public_key_hash, passphrase


//
// proxy/message-access.wsgi
//

squeakclient.proxy.read_message_access = request({url: '/proxy/message-access', method: 'GET'});
// node_name, from_user_key_hash, public_key_hash, passphrase
  
squeakclient.proxy.set_message_access = request({url: '/proxy/message-access', method: 'POST'});
// node_name, from_user_key_hash, access, public_key_hash, passphrase

squeakclient.proxy.delete_message_access = request({url: '/proxy/message-access', method: 'DELETE'});
// node_name, from_user_key_hash, public_key_hash, passphrase

//
// proxy/message-list.wsgi
//

squeakclient.proxy.read_message_list = request({url: '/proxy/message-list', method: 'GET'});
// node_name, to_user_key, from_user, from_user_key,
// start_time, end_time, max_records, order,
// public_key_hash, passphrase

//
// proxy/message-quota.wsgi
//

squeakclient.proxy.change_message_quota = request({url: '/proxy/message-quota', method: 'POST'});
// node_name, new_size, when_space_exhausted, public_key_hash, passphrase

squeakclient.proxy.read_message_quota = request({url: '/proxy/message-quota', method: 'GET'});
// node_name, public_key_hash, passphrase


//
// proxy/message.wsgi
//

squeakclient.proxy.read_message = request({url: '/proxy/message', method: 'GET'});
// node_name, message_id, public_key_hash, passphrase, to_key_passphrase, decrypt_message

squeakclient.proxy.send_message = request({url: '/proxy/message', method: 'POST'});
// node_name, to_user, to_user_key_hash, from_user_key_hash, message, passphrase, force_encryption

squeakclient.proxy.delete_message = request({url: '/proxy/message', method: 'DELETE'});
// node_name, message_id, public_key_hash, passphrase

//
// proxy/node.wsgi
//

//
// proxy/post-list.wsgi
//

squeakclient.proxy.read_post_list = request({url: '/proxy/post-list', method: 'GET'});
// node_name, group_id, owner_id, start_time, end_time, max_records, order, passphrase 


//
// proxy/post.wsgi
//

squeakclient.proxy.make_post = request({url: '/proxy/post', method: 'POST'});
// node_name, group_id, owner_id, data, passphrase, force_encryption


squeakclient.proxy.read_post = request({url: '/proxy/post', method: 'GET'});
// node_name, group_id, owner_id, post_id, passphrase, decrypt_post


squeakclient.proxy.delete_post = request({url: '/proxy/post', method: 'DELETE'});
// node_name, group_id, owner_id, post_id, passphrase


//
// proxy/user-quota.wsgi
//

squeakclient.proxy.change_user_quota = request({url: '/proxy/user-quota', method: 'POST'});
// node_name, new_size, user_class, auth_token, public_key_hash, passphrase


squeakclient.proxy.read_user_quota = request({url: '/proxy/user-quota', method: 'GET'});
// node_name, public_key_hash, passphrase


//
// proxy/query-user.wsgi
//

squeakclient.proxy.query_user = request({url: '/proxy/query-user', method: 'GET'});
// node_name, other_user_id


//
// proxy/user.wsgi
//

squeakclient.proxy.create_user = request({url: '/proxy/user', method: 'POST'});
// node_name, public_key_hash, default_message_access, when_mail_exhausted,
// quota_size, mail_quota_size, max_message_size, user_class, auth_token 

squeakclient.proxy.read_user = request({url: '/proxy/user', method: 'GET'});
// node_name, public_key_hash, passphrase

squeakclient.proxy.delete_user = request({url: '/proxy/user', method: 'DELETE'});
// node_name, public_key_hash, passphrase

//
// proxy/quota-available.wsgi
//

squeakclient.proxy.read_quota_available = request({url: '/proxy/quota-available', method: 'GET'});
// node_name, user_class


//
// proxy/version.wsgi
//

squeakclient.proxy.read_version = request({url: '/proxy/version', method: 'GET'});
// node_name

})();
