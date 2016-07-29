
// Converts base64 strings to data urls.

// requires bin64.js

(function() {

function DataToURL_BlobAndURL(mime_type, b64_data) {
    var 
        //binary_data = b64_data,
        //binary_data = atob(b64_data),
        binary_data = bin64_decode(b64_data),
        blob = new Blob([binary_data], {type: mime_type}),
        url = URL.createObjectURL(blob);

    return url;
}

function BlobAndURL_supported() {
    return window.Blob !== undefined &&
           window.URL !== undefined &&
           URL.createObjectURL !== undefined;
}

get_DataToURL = function() {
    if (BlobAndURL_supported()) {
        return DataToURL_BlobAndURL;
    }
    return null;
};

})();
