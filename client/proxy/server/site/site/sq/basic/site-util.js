

(function() {

debug = function(mesg) {
    $('#debug-message').append(mesg)
                       .append($('<br>'));
};

// generic error handling function
handle_error1 = function(resp, say) {
    if (resp.reason === 'bad session id') {
        window.location = 'login.html';
        return true;
    } else if (say && resp.reason === 'field required') {
        say('Field required: ' + resp.field);
        return true;
    } else if (say) {
        say(resp.reason);
        return true;
    }

    return false;
};


// Use this if a passphrase may need to be entered for a key.
handle_error2 = function(resp, say, key_purpose, pass_dialog, retry) {
    if (resp.reason === 'bad session id') {
        window.location = 'login.html';
        return true;
    } else if (resp.reason === 'bad passphrase') {
        pass_dialog.enqueue(key_purpose, resp.public_key_hash, retry);
    } else if (say && resp.reason === 'field required') {
        say('Field required: ' + resp.field);
        return true;
    } else if (say) {
        say(resp.reason);
        return true;
    }

    return false;
};


// add options to a select
append_select = function(select, values, get) {
    var length = values.length,
        i = 0;

    if (get === undefined) {
        get = function(x) {
            return x;
        };
    }

    for ( ; i < length; i++ ) {
        var opt = $('<option>'),
            value = get(values[i]);

        opt.val(value);
        opt.text(value);
        select.append(opt);
    }
};


// populate an html select with options.
refresh_select = function(select, values, get) {
    select.children().remove();

    append_select(select, values, get);
};

})();
