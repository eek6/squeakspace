
(function () {

group_string = function(node_name, owner_id, group_id) {
    return group_id + '.' + owner_id + '@' + node_name;
};

user_string = function(node_name, user_id) {
    return user_id + '@' + node_name;
};


debug = function(obj) {
};

/*
debug = function(obj) {
    $('#debug-message').append(JSON.stringify(obj))
                       .append($('<br>'));
};
*/


find_row_with_tag = function(array, key) {

    var length = array.length,
        i = 0;

    for ( ; i < length; i++ ) {
        var row = array[i];

        if (row !== null && row.length > 0 && row[0] === key) {
            return row;
        }
    }

    return null;
};

push_array = function(array, value) {
    array[array.length] = value;
};

get_timestamp = function() {
    return Math.round(Date.now());
};


// handlers = {state_changed(new_state), debug(obj), error(obj), done(mesg)}
// message is JSON object with no dictionaries.
MessageConstructor = function(from_key_hash, from_key_passphrase, message, handlers) {
    this.from_key_hash = from_key_hash;
    this.from_key_passphrase = from_key_passphrase;
    this.message = message;
    this.handlers = handlers;

    handlers.state_changed = handlers.state_changed || function(x) {};
    handlers.debug = handlers.debug || function(x) {};
    handlers.error = handlers.error || function(x) {};
    handlers.done = handlers.done || function() {};

    this.state = null;
    this.message_str = JSON.stringify(message);
    this.signature = null;
    this.output = null;
};

MessageConstructor.prototype.change_state = function(new_state) {
    this.state = new_state;
    this.handlers.state_changed(new_state);
};

MessageConstructor.prototype.start = function() {
    this.change_state('start');

    if (this.from_key_hash !== null) {
        this.sign();
    } else {
        this.output = JSON.stringify(
                {type: 'message',
                 from_key: null,
                 message: this.message});
        this.done();
    }
};

MessageConstructor.prototype.sign = function() {
    var trans = this;
    trans.change_state('sign');

    squeakclient.local.crypt.sign(
            {public_key_hash: trans.from_key_hash,
             data: trans.message_str,
             passphrase: trans.from_key_passphrase},
            function(resp, textStatus) {
                trans.handlers.debug(resp);

                if (resp.status === 'ok') {

                    trans.signature = resp.signature;
                    trans.output = JSON.stringify(
                        {type: 'message',
                         from_key: trans.from_key_hash,
                         message: trans.message,
                         signature: trans.signature});
                    trans.done();
                } else if (resp.status === 'error') {
                    trans.handlers.error(resp);
                }
            });
};

MessageConstructor.prototype.done = function() {
    this.change_state('done');
    this.handlers.done(this.output);
};


// handlers = { state_changed(new_state),
//              debug(obj),
//              error(obj),
//              fail(obj),
//              verified(message_obj, from_node, from_user, from_key, trust_score),
//              not_signed(message_obj),
//            }
MessageVerifier = function(data, user_id, handlers) {
    this.data = data;
    this.user_id = user_id;
    this.handlers = handlers;

    handlers.state_changed = handlers.state_changed || function(x) {};
    handlers.debug = handlers.debug || function(x) {};
    handlers.error = handlers.error || function(x) {};

    this.state = null;
    this.data_obj = null;
    this.from_key = null;
    this.message_obj = null;
    this.message_str = null;
    this.signature = null;
    this.signature_valid = null;
    this.from_node = null;
    this.from_user = null;
};

MessageVerifier.prototype.change_state = function(new_state) {
    this.state = new_state;
    this.handlers.state_changed(new_state);
};


MessageVerifier.prototype.start = function() {
    this.change_state('start');
    this.parse();
};

MessageVerifier.prototype.parse = function() {
    this.change_state('parse');

    try {
        this.data_obj = JSON.parse(this.data);
    } catch(e) {
        this.handlers.fail(
                {reason: 'message_malformed',
                 data: this.data});
    }

    var data_obj = this.data_obj;

    if (data_obj.type !== 'message' ||
        data_obj.from_key === undefined ||
        data_obj.message === undefined ||
        (data_obj.from_key !== null &&
         data_obj.signature === undefined)) {
        this.handlers.fail(
                {reason: 'message_malformed',
                 data: this.data});
    } else {
        this.from_key = data_obj.from_key;
        this.message_obj = data_obj.message;
        this.signature = data_obj.signature;

        if (this.from_key !== null) {
            this.message_str = JSON.stringify(this.message_obj);
            this.verify_signature();
        } else {
            this.not_signed();
        }
    }
};

MessageVerifier.prototype.verify_signature = function() {
    var trans = this;
    trans.change_state('verify_signature');

    squeakclient.local.crypt.verify_signature(
            {public_key_hash: trans.from_key,
             data: trans.message_str,
             signature: trans.signature},
            function(resp, textStatus) {
                trans.handlers.debug(resp);

                if (resp.status === 'ok') {
                    trans.signature_valid = resp.valid;

                    if (trans.signature_valid) {
                        trans.parse_from();
                    } else {
                        trans.signature_invalid();
                    }
                } else if (resp.status === 'error') {
                    if (resp.reason === 'key not found') {
                        trans.key_not_found();
                    } else {
                        trans.handlers.error(resp);
                    }
                }
            });
};

MessageVerifier.prototype.parse_from = function() {
    this.change_state('parse_from');

    var from_row = find_row_with_tag(this.message_obj, 'from');

    if (from_row === null || from_row.length !== 4) {
        this.no_from_tag();
    } else {
        var from_node = from_row[1],
            from_user = from_row[2],
            from_key = from_row[3];

        if (from_key !== this.from_key) {
            this.no_from_tag();
        } else {
            this.from_node = from_node;
            this.from_user = from_user;
            this.verify_from_user();
        }
    }
};

MessageVerifier.prototype.verify_from_user = function() {
    var trans = this;
    trans.change_state('verify_from_user');

    squeakclient.local.read_other_user_key(
            {other_user_id: trans.from_user,
             node_name: trans.from_node,
             public_key_hash: trans.from_key},
            function(resp, textStatus) {
                trans.handlers.debug(resp);

                if (resp.status === 'ok') {
                    var key = resp.key;

                    trans.trust_score = key.trust_score;
                    trans.verified();
                } else if (resp.status === 'error') {
                    if (resp.reason === 'user key not found') {
                        if (trans.user_id === trans.from_user) {
                            trans.try_own_key();
                        } else {
                            trans.wrong_key();
                        }
                    } else {
                        trans.handlers.error(resp);
                    }
                }
            });
};

MessageVerifier.prototype.try_own_key = function() {
    var trans = this;
    trans.change_state('try_own_key');

    squeakclient.local.read_user_key(
            {node_name: trans.from_node,
             public_key_hash: trans.from_key},
            function(resp, textStatus) {
                trans.handlers.debug(resp);

                if (resp.status === 'ok') {
                    var key = resp.key;

                    trans.trust_score = 'self';
                    trans.verified();
                } else if (resp.status === 'error') {
                    if (resp.reason === 'user key not found') {
                        trans.wrong_key();
                    } else {
                        trans.handlers.error(resp);
                    }
                }
            });
};

MessageVerifier.prototype.verified = function() {
    this.change_state('verified');
    this.handlers.verified(
            this.message_obj, this.from_node, this.from_user,
            this.from_key, this.trust_score);
};

MessageVerifier.prototype.wrong_key = function() {
    this.change_state('wrong_key');
    this.handlers.fail(
            {reason: 'wrong_key',
             from_node: this.from_node,
             from_user: this.from_user,
             from_key: this.from_key,
             message: this.message_obj});
};

MessageVerifier.prototype.no_from_tag = function() {
    this.change_state('no_from_tag');
    this.handlers.fail(
            {reason: 'no_from_tag',
             message: this.message_obj});
};

MessageVerifier.prototype.key_not_found = function() {
    this.change_state('key_not_found');
    this.handlers.fail(
            {reason: 'key_not_found',
             from_key: this.from_key,
             message: this.message_obj});
};

MessageVerifier.prototype.signature_invalid = function() {
    this.change_state('signature_invalid');
    this.handlers.fail(
            {reason: 'signature_invalid',
             from_key: this.from_key,
             message: this.message_obj});
};


MessageVerifier.prototype.not_signed = function() {
    this.change_state('not_signed');
    this.handlers.not_signed(this.message_obj);
};


// handlers = { state_changed(new_state),
//              debug(obj),
//              error(obj),
//              proxy_error(obj),
//              blocked(),
//              sent(message_id, timestamp, message_hash, from_signature, proof_of_work)
//              ask_from_sig(callback), // callback(from_user_key_hash, from_user_key_passphrase)
//            }
SendMessageTransaction = function(node_name, to_user, to_key, message, handlers) {
    this.node_name = node_name;
    this.to_user = to_user;
    this.to_key = to_key;
    this.message = message;
    this.handlers = handlers;

    handlers.state_changed = handlers.state_changed || function(x) {};
    handlers.debug = handlers.debug || function(x) {};
    handlers.error = handlers.error || function(x) {};
    handlers.proxy_error = handlers.proxy_error || function(x) {};

    this.state = null;
    this.default_message_access = null;
    this.from_user_key_hash = null;
    this.from_user_key_passphrase = null;
    this.key_message_access = null;
    this.message_id = null;
    this.timestamp = null;
    this.message_hash = null;
    this.from_signature = null;
    this.proof_of_work = null;
};

SendMessageTransaction.prototype.change_state = function(new_state) {
    this.state = new_state;
    this.handlers.state_changed(new_state);
};

SendMessageTransaction.prototype.start = function() {
    this.change_state('start');
    this.query_default_message_access();
};

SendMessageTransaction.prototype.query_default_message_access = function() {
    var trans = this;
    trans.change_state('query_default_message_access()');

    squeakclient.proxy.query_message_access(
            {node_name: trans.node_name,
             to_user: trans.to_user,
             from_user_key_hash: null,
             passphrase: null},
            function(resp, textStatus) {
                trans.handlers.debug(resp);

                if (resp.status === 'ok') {
                    var proxy_resp = resp.resp;

                    if (proxy_resp.status === 'ok') {
                        var message_access = proxy_resp.message_access.access;

                        trans.default_message_access = message_access;

                        if (message_access === 'block') {
                            trans.handlers.ask_from_sig(
                                function(from_user_key_hash, from_user_key_passphrase) {
                                    trans.from_user_key_hash = from_user_key_hash;
                                    trans.from_user_key_passphrase = from_user_key_passphrase;

                                    trans.query_message_access();
                                });
                        } else {
                            // TODO: Should Non-anonymous mail be preferred if it avoids hashcash?

                            trans.send_message();
                        }
                    } else if (proxy_resp.status === 'error') {
                        trans.handlers.proxy_error(proxy_resp);
                    }
                } else if (resp.status === 'error') {
                    trans.handlers.error(resp);
                }
            });
};

SendMessageTransaction.prototype.query_message_access = function() {
    var trans = this;
    trans.change_state('query_message_access');

    squeakclient.proxy.query_message_access(
            {node_name: trans.node_name,
             to_user: trans.to_user,
             from_user_key_hash: trans.from_user_key_hash,
             passphrase: trans.from_user_key_passphrase},
            function(resp, textStatus) {
                trans.handlers.debug(resp);

                if (resp.status === 'ok') {
                    var proxy_resp = resp.resp;

                    if (proxy_resp.status === 'ok') {
                        var message_access = proxy_resp.message_access.access;

                        trans.key_message_access = message_access;

                        if (message_access === 'block') {
                            trans.handlers.blocked();
                        } else {
                            trans.send_signed_message();
                        }
                    } else if (proxy_resp.status === 'error') {
                        trans.handlers.proxy_error(proxy_resp);
                    }
                } else if (resp.status === 'error') {
                    trans.handlers.error(resp);
                }
            });
};

SendMessageTransaction.prototype.send_message = function() {
    var trans = this;
    trans.change_state('send_message');

    squeakclient.proxy.send_message(
            {node_name: trans.node_name,
             to_user: trans.to_user,
             to_user_key_hash: trans.to_key,
             from_user_key_hash: null,
             message: trans.message,
             passphrase: null,
             force_encryption: true},
            function(resp, textStatus) {
                trans.handlers.debug(resp);

                if (resp.status === 'ok') {
                    var proxy_resp = resp.resp;

                    if (proxy_resp.status === 'ok') {
                        trans.message_id = resp.message_id;
                        trans.timestamp = resp.timestamp;
                        trans.message_hash = resp.message_hash;
                        trans.from_signature = resp.from_signature;
                        trans.proof_of_work = resp.proof_of_work;

                        trans.done();
                    } else if (proxy_resp.status === 'error') {
                        trans.handlers.proxy_error(proxy_resp);
                    }
                } else if (resp.status === 'error') {
                    trans.handlers.error(resp);
                }
            });
};

SendMessageTransaction.prototype.send_signed_message = function() {
    var trans = this;
    trans.change_state('send_signed_message');

    squeakclient.proxy.send_message(
            {node_name: trans.node_name,
             to_user: trans.to_user,
             to_user_key_hash: trans.to_key,
             from_user_key_hash: trans.from_user_key_hash,
             message: trans.message,
             passphrase: trans.from_user_key_passphrase,
             force_encryption: true},
            function(resp, textStatus) {
                trans.handlers.debug(resp);

                if (resp.status === 'ok') {
                    var proxy_resp = resp.resp;

                    if (proxy_resp.status === 'ok') {
                        trans.message_id = resp.message_id,
                        trans.timestamp = resp.timestamp,
                        trans.message_hash = resp.message_hash,
                        trans.from_signature = resp.from_signature,
                        trans.proof_of_work = resp.proof_of_work;

                        trans.done();
                    } else if (proxy_resp.status === 'error') {
                        trans.handlers.proxy_error(proxy_resp);
                    }
                } else if (resp.status === 'error') {
                    trans.handlers.error(resp);
                }
            });
};

SendMessageTransaction.prototype.done = function() {
    this.change_state('done');
    this.handlers.sent(
            this.message_id, this.timestamp, this.message_hash,
            this.from_signature, this.proof_of_work);
};

 
})();
