

// querystring-0.0.0.js
// parses query strings 

(function () {

querystring = {};

querystring.parse = function(qs) {
    var pair_strings = qs.replace(/\+/g, " ").split('&'),
        length = pair_strings.length,
        i = 0,
        params = {};

    for ( ; i < length; i++ ) {
        var pair_string = pair_strings[i],
            equal_index = pair_string.search('=');

        if (equal_index === -1) {
            throw new Error();
        }

        var enc_key = pair_string.substring(0, equal_index),
            enc_value = pair_string.substring(equal_index + 1),
            key = null,
            value = null;

        try {
            key = decodeURIComponent(enc_key);
            value = decodeURIComponent(enc_value);
        } catch (e) {
            return null;
        }

        params[key] = value;
    }

    return params;
}

querystring.load = function() {

    var url = window.location.toString(),
        i = url.indexOf('?');

    if (i === -1) {
        return null;
    } else {
        var qs = url.substring(i + 1);

        try {
            return querystring.parse(qs);
        } catch (e) {
            alert("malformed query string");
            return null;
        }
    }
}

})();

