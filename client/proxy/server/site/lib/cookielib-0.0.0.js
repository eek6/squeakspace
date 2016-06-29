
(function () {

cookielib = {};

cookielib.set = function(key, value) {
    document.cookie = encodeURIComponent(key) + '=' + encodeURIComponent(value) + '; Path=/'
};

cookielib.parse = function(key) {
    var key_pairs = document.cookie.split('; '),
        cookies = {},
        length = key_pairs.length,
        i = 0;

    for ( ; i < length; i++ ) {
        var key_pair = key_pairs[i],
            equal_index = key_pair.indexOf('='),
            enc_key = key_pair.substring(0, equal_index),
            enc_value = key_pair.substring(equal_index + 1),
            key = decodeURIComponent(enc_key),
            value = decodeURIComponent(enc_value);

        cookies[key] = value;
    }

    return cookies;
}

cookielib.del = function(key) {
    document.cookie = encodeURIComponent(key) + "=; Path=/; expires=Thu, 01 Jan 1970 00:00:00 UTC"; 
};

cookielib.clear = function() {
    for ( var cookie_name in cookielib.parse() ) {
        cookielib.del(cookie_name);
    }
};

})();
