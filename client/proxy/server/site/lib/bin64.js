
// bin64 is a javascript base64 library that only
// supports encoding Uint8Array. It's written to
// be fast and self contained. It doesn't check
// for errors when decoding.
//
// equal signs in the middle of the string are
// allowed and treated as zeros.

(function() {

var table = [
    'A', //  0
    'B', //  1
    'C', //  2
    'D', //  3
    'E', //  4
    'F', //  5
    'G', //  6
    'H', //  7
    'I', //  8
    'J', //  9
    'K', // 10
    'L', // 11
    'M', // 12
    'N', // 13
    'O', // 14
    'P', // 15
    'Q', // 16
    'R', // 17
    'S', // 18
    'T', // 19
    'U', // 20
    'V', // 21
    'W', // 22
    'X', // 23
    'Y', // 24
    'Z', // 25
    'a', // 26
    'b', // 27
    'c', // 28
    'd', // 29
    'e', // 30
    'f', // 31
    'g', // 32
    'h', // 33
    'i', // 34
    'j', // 35
    'k', // 36
    'l', // 37
    'm', // 38
    'n', // 39
    'o', // 40
    'p', // 41
    'q', // 42
    'r', // 43
    's', // 44
    't', // 45
    'u', // 46
    'v', // 47
    'w', // 48
    'x', // 49
    'y', // 50
    'z', // 51
    '0', // 52
    '1', // 53
    '2', // 54
    '3', // 55
    '4', // 56
    '5', // 57
    '6', // 58
    '7', // 59
    '8', // 60
    '9', // 61
    '+', // 62
    '/'  // 63
];

var inverse_table = {};

for ( var i = 0; i < 64; i++ ) {
    inverse_table[table[i]] = i;
}

inverse_table['='] = 0;

bin64_encode = function(byte_array) {
    var out_str = [],
        i = 0,
        length = byte_array.length,
        length3 = Math.floor(length/3)*3;

    for ( ; i < length3; i += 3) {
        var byte1 = byte_array[i];
        var byte2 = byte_array[i + 1];
        var byte3 = byte_array[i + 2];

        var out1 = byte1 >> 2;
        var out2 = ((byte1 << 4) & 63) | (byte2 >> 4);
        var out3 = ((byte2 << 2) & 63) | (byte3 >> 6);
        var out4 = byte3 & 63;

        out_str.push(table[out1]);
        out_str.push(table[out2]);
        out_str.push(table[out3]);
        out_str.push(table[out4]);
    }

    if (i < length) {
        var byte1 = byte_array[i];
        var out1 = byte1 >> 2;

        out_str.push(table[out1]);

        if (i + 1 < length) {
            var byte2 = byte_array[i + 1];
            var out2 = ((byte1 << 4) & 63) | (byte2 >> 4);
            var out3 = ((byte2 << 2) & 63);

            out_str.push(table[out2]);
            out_str.push(table[out3]);
            out_str.push('=');
        } else {
            var out2 = ((byte1 << 4) & 63);
            out_str.push(table[out2]);
            out_str.push('=');
            out_str.push('=');
        }
    }

    return out_str.join('');
};

bin64_decode = function(b64_str) {

    var str_length = b64_str.length,
        padding_length = 0;

    for ( ; padding_length < str_length; padding_length++ ) {
        var i = str_length - padding_length - 1;
        if (b64_str[i] !== '=')
            break;
    }

    var length = str_length - padding_length,
        chunks = Math.floor(length/4),
        length4 = chunks*4,
        extra_bytes = padding_length % 3;

    if (extra_bytes !== 0)
        extra_bytes = 3 - extra_bytes;

    var data_length = chunks*3 + extra_bytes;

    var out_data = new Uint8Array(data_length),
        b64_i = 0,
        data_i = 0;

    while(b64_i < length4) {
        var in1 = inverse_table[b64_str[b64_i]];
        var in2 = inverse_table[b64_str[b64_i + 1]];
        var in3 = inverse_table[b64_str[b64_i + 2]];
        var in4 = inverse_table[b64_str[b64_i + 3]];

        out_data[data_i] = (in1 << 2) | (in2 >> 4);
        out_data[data_i + 1] = ((in2 << 4) & 0xff) | (in3 >> 2);
        out_data[data_i + 2] = ((in3 << 6) & 0xff) | in4;

        b64_i += 4;
        data_i += 3;
    }

    if (data_i < data_length) {
        var in1 = inverse_table[b64_str[b64_i]];
        var in2 = inverse_table[b64_str[b64_i + 1]];

        out_data[data_i] = (in1 << 2) | (in2 >> 4);

        if (data_i + 1 < data_length) {
            var in3 = inverse_table[b64_str[b64_i + 2]];

            out_data[data_i + 1] = ((in2 << 4) & 0xff) | (in3 >> 2);
        }
    }

    return out_data;
};

})();
