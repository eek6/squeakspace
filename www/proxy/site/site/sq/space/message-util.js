
// requires data-to-url.js

(function() {

var DataToUrl = get_DataToURL();

load_message_obj = function(message_obj, div_data) {

    var to_row = find_row_with_tag(message_obj, 'to'),
        from_row = find_row_with_tag(message_obj, 'from'),
        time_row = find_row_with_tag(message_obj, 'time'),
        re_row = find_row_with_tag(message_obj, 're'),
        message_row = find_row_with_tag(message_obj, 'message'),
        invite_row = find_row_with_tag(message_obj, 'invite'),
        files_row = find_row_with_tag(message_obj, 'files');

    if (time_row !== undefined && time_row.length === 2) {
        div_data.id.timestamp = time_row[1];
    }

    if (to_row !== null && to_row.length === 4) {
        var to_node = to_row[1],
            to_user = to_row[2],
            to_key_hash = to_row[3];

        div_data.to = {};
        div_data.to.node = to_node;
        div_data.to.user = to_user;
        div_data.to.user_string = user_string(to_node, to_user);
        div_data.to.key_hash = to_key_hash;
    }

    if (from_row !== null && from_row.length === 4) {
        var from_node = from_row[1],
            from_user = from_row[2],
            from_key = from_row[3];

        div_data.from = {};
        div_data.from.node = from_node;
        div_data.from.user = from_user;
        div_data.from.user_string = user_string(from_node, from_user);
        div_data.from.key_hash = from_key;
    }

    if (re_row !== null && re_row.length === 2) {
        var reply_to = re_row[1];

        div_data.re = reply_to;
    }

    if (message_row !== null && message_row.length === 2) {
        var text = message_row[1];

        div_data.text = text;
    }

    if (invite_row !== null && invite_row.length === 2) {
        var invite_obj = invite_row[1];

        div_data.invite = invite_obj;
    }

    if (files_row !== null && files_row.length === 2) {
        var files_array = files_row[1];

        div_data.files = files_array;
    }
};


publish_message = function(block_div, div_data, inner_validation, outer_validation) {

    if (inner_validation.status === 'verified') {

        var trust_score = inner_validation.trust_score,
            message_obj = inner_validation.message;

        load_message_obj(message_obj, div_data);

        if (div_data.from !== undefined) {
            div_data.from.trust_score = trust_score;
            div_data.from.signature_state = 'Signature Verified';
        }

    } else if (inner_validation.status === 'not_signed') {

        var message_obj = inner_validation.message;

        load_message_obj(message_obj, div_data);

        if (div_data.from !== undefined) {
            div_data.from.signature_state = 'Not Signed';
        }

    } else if (inner_validation.status === 'failed') {

        var report = inner_validation.report;

        if (report.reason === 'message_malformed') {

            div_data.text = report.data;
            div_data.error = 'Message Malformed';

        } else if (report.reason === 'wrong_key') {

            var message_obj = report.message;

            load_message_obj(message_obj, div_data);

            div_data.error = 'Message is signed by a key that does not belong to the from user.';

        } else if (report.reason === 'no_from_tag') {

            var message_obj = report.message;

            load_message_obj(message_obj, div_data);

            div_data.error = 'Message is signed by a key but has no from tag.';

        } else if (report.reason === 'key_not_found') {

            var message_obj = report.message;

            load_message_obj(message_obj, div_data);

            div_data.error = 'Message signature cannot be verified because the signing key is not found.';

        } else if (report.reason === 'signature_invalid') {

            var message_obj = report.message;

            load_message_obj(message_obj, div_data);

            div_data.error = 'Message signature is invalid.';
        }
    }

    var html_div = create_message_div(div_data);

    block_div.append(html_div);
};


write_message_text = function(div, raw_message_text) {
    var split = raw_message_text.split('\n'),
        length = split.length,
        i = 0;

    for ( i = 0; i < length; i++ ) {
        div.append(split[i]).append($('<br/>'));
    }
};

mime_to_div_table = {
    image: function(mime_type, b64_data) {
        var url = DataToUrl(mime_type, b64_data),
            img = $('<img>').attr('src', url)
                            .attr('class', 'thumbnail'),
            link = $('<a>').attr('href', url).append(img),
            div = $('<div>').attr('class', 'attachment')
                            .append(link);

        return div;
    },
    video: function(mime_type, b64_data) {
        var url = DataToUrl(mime_type, b64_data),
            video = $('<video>').attr('src', url)
                                .attr('controls', 'controls')
                                .attr('class', 'video'),
            link = $('<a>').attr('href', url).append('Open'),
            link_div = $('<div>').append(link),
            div = $('<div>').attr('class', 'attachment')
                            .append(video)
                            .append(link_div);

        return div;
    },
    audio: function(mime_type, b64_data) {
        var url = DataToUrl(mime_type, b64_data),
            audio = $('<audio>').attr('src', url)
                                .attr('controls', 'controls')
                                .attr('class', 'audio'),
            link = $('<a>').attr('href', url).append('Open'),
            link_div = $('<div>').append(link),
            div = $('<div>').attr('class', 'attachment')
                            .append(audio)
                            .append(link_div);

        return div;
    },
    text: function(mime_type, b64_data) {
        //var url = DataToUrl(mime_type, b64_data);
        //return $('<div>').append($('<image>').attr('src', url));
        var text_data = atob(b64_data);
        return $('<div>').attr('class', 'attachment')
                         .text(text_data);
    }
};

// Just have a link to it.
default_file_div = function(mime_type, b64_data) {
    var url = DataToUrl(mime_type, b64_data);
    return $('<div>').append($('<a>').attr('href', url)
                                     .text('Click'));
}

// data = { id: {hash: ,
//               timestamp: },
//          to: {user_string: ,
//               key_hash: },
//          encrypted_to_key: ,
//          from: {user_string: ,
//                 key_hash: ,
//                 trust_score: ,
//                 signature_state: },
//          error: ,
//          text: ,
//          invite: [key_exports, group_keys] }
//
// uses globals: default_identity
//               can_reply_to_anonymous
create_message_div = function(data) {

    var div = $('#templates').find('.message-div').clone(),
        id_div = div.find('.id-div');

    if (data.id === undefined) {
        id_div.remove();
    } else {
        id_div.find('.timestamp').append(data.id.timestamp);
        id_div.find('.hash').append(data.id.hash);

        div.attr('id', 'id_' + data.id.hash);
    }

    var to_div = div.find('.to-div');
    if (data.to === undefined) {
        to_div.remove();
    } else {
        to_div.find('.user-link').text(data.to.user_string)
                                 .attr('href', 'contact.html?'
                                         + $.param({node: data.to.node,
                                                    user: data.to.user,
                                                    key: data.to.key_hash}));
        to_div.find('.key-hash').append(data.to.key_hash);
    }

    var from_div = div.find('.from-div'),
        reply_div = div.find('.reply-div');
    if (data.from === undefined) {
        from_div.find('.from').remove();
        if (!can_reply_to_anonymous) {
            reply_div.remove();
        }
    } else {
        from_div.find('.from-anonymous').remove();

        var data_div = from_div.find('.data-div'),
            from = from_div.find('.from'),
            contact_link = 'contact.html?' +
                $.param({node: data.from.node,
                         user: data.from.user,
                         key: data.from.key_hash});

        data_div.find('.node').append(data.from.node);
        data_div.find('.user').append(data.from.user);
        data_div.find('.key-hash').append(data.from.key_hash);

        from.find('.user-link').text(data.from.user_string)
                               .attr('href', contact_link);

        from.find('.key-hash').append(data.from.key_hash);

        if (data.from.trust_score === undefined) {
            from.find('.trust-span').remove();
        } else {
            from.find('.trust-score').append(data.from.trust_score);
        }

        from.find('.signature-status').append(data.from.signature_status);
    }

    var re_div = div.find('.re-div');
    if (data.re === undefined) {
        re_div.remove();
    } else {
        re_div.find('.re-link').text(data.re)
                               .attr('href', '#id_' + data.re);
    }

    if (data.encrypted_to_key !== null) {
        div.find('.unencrypted-warning').remove();
    }

    var text_div = div.find('.text-div');
    if (data.text === undefined) {
        text_div.remove();
    } else {
        var text = text_div.find('.text');
        write_message_text(text, data.text);
    }

    var files_div = div.find('.files-div');
    if (data.files === undefined) {
        files_div.remove();
    } else {
        var files_array = data.files,
            i = 0,
            length = files_array.length;

        for ( ; i < length; i++ ) {
            var file_obj = files_array[i],
                mime_type = file_obj[0],
                mime_split = mime_type.split('/'),
                b64_data = file_obj[1],
                div_maker = mime_to_div_table[mime_split[0]] || default_file_div;

            //alert(i + ' ' + mime_type);

            if (DataToUrl === null) {
                files_div.append($('<div>').text('Attachment loading not supported'));
            //} else if (div_maker === undefined) {
            //    files_div.append($('<div>').text('Mime type unsupported: ' + mime_type));
            } else {
                files_div.append(div_maker(mime_type, b64_data));
            }
        }
    }

    var invite_div = div.find('.invite-div');
    if (data.invite === undefined) {
        invite_div.remove();
    } else {
        var data_div = invite_div.find('.data-div'),
            group_key_list = invite_div.find('.group-key-list'),
            invite_obj = data.invite,
            group_keys = invite_obj[1],
            l1 = group_keys.length,
            i = 0;

        data_div.text(JSON.stringify(invite_obj));

        for ( ; i < l1 ; i++ ) {
            var group_key = group_keys[i],
                key_hash = group_key[0],
                access_array = group_key[1],
                l2 = access_array.length,
                j = 0,
                group_key_row = $('#templates').find('.group-key-row').clone(),
                key_hash_td = group_key_row.find('.key-hash'),
                group_access_td = group_key_row.find('.group-access');

            key_hash_td.text(key_hash);

            for ( ; j < l2; j++ ) {
                var access_obj = access_array[j],
                    node_name = access_obj[0],
                    owner_id = access_obj[1],
                    group_id = access_obj[2],
                    key_use = access_obj[3],
                    group_str = group_string(node_name, owner_id, group_id),
                    group_access_div = $('#templates').find('.group-access-div').clone();

                group_access_div.find('.group-name').text(group_str);
                group_access_div.find('.key-use').text(key_use);
                group_access_td.append(group_access_div);
            }

            group_key_list.append(group_key_row);
        }
    }

    var error_div = div.find('.error-div');
    if (data.error === undefined) {
        error_div.remove();
    } else {
        error_div.append(data.error);
        text_div.find('.text-button').show();
        text_div.find('.text').hide();
    }

    var reply_div = div.find('.reply-div');
    reply_div.find('.reply-as-select').val(default_identity);

    return div;
};



AcceptInvitationTransaction = function(invitation_obj, handlers) {
    this.invitation_obj = invitation_obj;
    this.handlers = handlers;

    handlers.error = handlers.error || function(x) {};
    handlers.debug = handlers.debug || function(x) {};
    handlers.fail = handlers.fail || function(x) {};
    handlers.done = handlers.done || function() {};

    this.key_exports = null;
    this.group_keys = null;
};


AcceptInvitationTransaction.prototype.start = function() {
    this.validate();
};

AcceptInvitationTransaction.prototype.start = function() {
    this.key_exports = this.invitation_obj[0];
    this.group_keys = this.invitation_obj[1];

    this.import_key_step(0);
};

AcceptInvitationTransaction.prototype.import_key_step = function(i) {
    var trans = this;

    if (i < trans.key_exports.length) {

        var key = trans.key_exports[i],
            public_key_hash = key[0],
            key_type = key[1],
            public_key = key[2],
            revoke_date = key[3],
            private_key = key[4];

        squeakclient.local.import_private_key(
                {key_type: key_type,
                 public_key: public_key,
                 private_key: private_key,
                 revoke_date: revoke_date},
                function(resp, textStatus) {
                    trans.handlers.debug(resp);

                    if (resp.status === 'ok') {
                        var resp_pkh = resp.public_key_hash;
    
                        if (resp_pkh === public_key_hash) {
                            trans.import_key_step(i + 1); 
                        } else {
                            trans.handlers.fail(
                                {reason: 'public_key_hash_does_not_match',
                                 step: 'import_key',
                                 index: i});
                        }

                    } else if (resp.status === 'error') {
                        if (resp.reason === 'key exists') {
                            if (resp.match === true) {
                                // The key we want is already there. Recover.
                                trans.import_key_step(i + 1); 
                            } else {
                                trans.handlers.fail(
                                        {reason: 'public_key_hash_collision',
                                         step: 'import_key',
                                         index: i});
                            }
                        } else {
                            trans.handlers.error(resp);
                        }
                    }
                });
    } else {
        trans.group_key_step(0, 0);
    }
};

AcceptInvitationTransaction.prototype.group_key_step = function(i, j) {
    var trans = this;

    if (i < trans.group_keys.length) {

        var group_key = trans.group_keys[i],
            key_hash = group_key[0],
            access_array = group_key[1];

        if (j < access_array.length) {

            var access_obj = access_array[j],
                node_name = access_obj[0],
                owner_id = access_obj[1],
                group_id = access_obj[2],
                key_use = access_obj[3];

            squeakclient.local.assign_group_key(
                    {group_id: group_id,
                     owner_id: owner_id,
                     node_name: node_name,
                     key_use: key_use,
                     public_key_hash: key_hash},
                    function(resp, textStatus) {
                        trans.handlers.debug(resp);

                        if (resp.status === 'ok') {
                            trans.group_key_step(i, j + 1);
                        } else if (resp.status === 'error') {
                            trans.handlers.error(resp);
                        }
                    });
        } else {
            trans.group_key_step(i + 1, 0);
        }

    } else {
        trans.handlers.done();
    }
};

// Interface between MessageVerifier and the validate_post method
// required by PostsWindowManager.
validate_message = function(message, user_id, debug, handle_error, callback) {
    var handlers = {
            state_changed: function(new_state) {
            },
            debug: debug,
            error: handle_error,
            fail: function(obj) {
                callback({status: 'failed',
                          report: obj});
            },
            verified: function(message_obj, from_node, from_user, from_key, trust_score) {
                callback({status: 'verified',
                          message: message_obj,
                          from_node: from_node,
                          from_user: from_user,
                          from_key: from_key,
                          trust_score: trust_score});
            },
            not_signed: function(message_obj) {
                callback({status: 'not_signed',
                          message: message_obj});
            }
        },
        verifier = new MessageVerifier(message, user_id, handlers);

    verifier.start();
};


})();
