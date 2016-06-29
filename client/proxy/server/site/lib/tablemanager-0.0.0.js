// tablemanager-0.0.0.js

// defines a class generates tabled data.

(function() {

var check_box = function() {
    return $('<input>').attr('type', 'checkbox');
};

TableManager = function(root) {
    this.root = root;
};

TableManager.prototype.addRow = function(row_data) {
    var row = $('<tr>'),
        i = 0,
        length = row_data.length;

    $('<td>').append(check_box()).appendTo(row);

    for ( ; i < length; i++ ) {
        $('<td>').append(row_data[i]).appendTo(row);
    }
    row.appendTo(this.root);

    //alert(JSON.stringify(this.root));
};

TableManager.prototype.forBoxes = function(f) {
    var rows = this.root.children(),
        length = rows.length,
        i = 0;

    for ( ; i < length; i++ ) {
        var row = $(rows[i]),
            cells = row.children(),
            row_length = cells.length,
            j = 0;

        if (row_length > 0) {
            var cell = cells[0],
                box = $(cell).children()[0];

            f(box);
        }
    }
};

TableManager.prototype.forCheckedRows = function(f) {
    var rows = this.root.children(),
        length = rows.length,
        i = 0;

    for ( ; i < length; i++ ) {
        var row = $(rows[i]),
            cells = row.children(),
            row_length = cells.length,
            j = 0;

        if (row_length > 0) {
            var cell = cells[0],
                box = $(cell).children()[0];

            if (box.checked) {
                f(row);
            }
        }
    }
};



TableManager.prototype.invertBoxes = function() {
    this.forBoxes(
            function(box) {
                box.checked = !box.checked;
            });
};

TableManager.prototype.checkAllBoxes = function () {
    this.forBoxes(
            function(box) {
                box.checked = true;
            });
};

TableManager.prototype.clearAllBoxes = function () {
    this.forBoxes(
            function(box) {
                box.checked = false;
            });
};

TableManager.prototype.clear = function() {
    this.root.children().remove();
};

})();
