
// FileLoader takes an input element of type="file",
//   goes through its file_list and collects an array
//   of pairs, mime type and the file as a binary string.
//
// 
// Use: get_FileLoader()(file_input, handlers)
// where handlers = {done(values), error(i)}
//
// requires bin64.js


(function() {



// handlers = {done(values), error()}
function FileLoader_FileAPI(file_input, handlers) {
    var trans = this;

    trans.handlers = handlers;
    trans.reader = new FileReader();
    trans.file_list = file_input.files;
    trans.length = trans.file_list.length;
    trans.values = [];
    trans.i = null;

    trans.reader.onload = function() {
        trans.step_done(trans.reader.result);
    };

    trans.reader.onerror = function() {
        trans.handlers.error(trans.i, trans.reader.error);
    };
}

FileLoader_FileAPI.prototype.start = function() {
    this.i = 0;
    this.step();
};

FileLoader_FileAPI.prototype.step = function() {
    var i = this.i,
        length = this.length;

    if (i < length) {

        var file = this.file_list[i],
            type = file.type;

        this.values[i] = [type, null];

        this.reader.readAsArrayBuffer(file);
    } else {
        this.handlers.done(this.values);
    }
};

FileLoader_FileAPI.prototype.step_done = function(data) {
    this.values[this.i][1] = bin64_encode(new Uint8Array(data));
    //alert('encoded: ' + this.values[this.i][1]);
    //this.values[this.i][1] = btoa(data);
    //this.values[this.i][1] = data;
    this.i++;
    this.step();
};


function FileAPI_supported() {
    return window.File !== undefined &&
           window.FileReader !== undefined;
}

get_FileLoader = function() {
    if (FileAPI_supported()) {
        return FileLoader_FileAPI;
    }

    return null;
};


})();
