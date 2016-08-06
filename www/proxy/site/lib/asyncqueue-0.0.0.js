
// asyncqueue-0.0.0.js

(function() {

// tasks is an array of objects,
// where each object has a status code
// as a key and a hander as a value.
// Each handler is a function accepting (this, data),
// where this is a reference to this AsyncQueue
// and data is user data.

AsyncQueue = function(tasks) {
    this.i = 0;
    this.queue = tasks;
}

AsyncQueue.prototype.append = function(task) {
    this.queue[this.queue.length] = task
}

AsyncQueue.prototype.do_next = function(status, data) {
    if (this.i < this.queue.length) {
        var index = this.i;
        this.i++;

        var handler = this.queue[index][status];

        if (handler !== undefined) {
            handler(this, data);
        }
    }
}

AsyncQueue.prototype.has_tasks = function() {
    return this.i < this.queue.length;
}

})();
