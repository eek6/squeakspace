// taskqueue-0.0.0.js

(function() {

TaskQueue = function(tasks) {
    this.queue = tasks;
}

TaskQueue.prototype.append = function(task) {
    this.queue[this.queue.length] = task
}

TaskQueue.prototype.execute = function() {
    var i = 0;

    for ( ; i < this.queue.length; i++ ) {
        this.queue[i]();
    }

    this.queue = [];
}

TaskQueue.prototype.has_tasks = function() {
    return this.queue.length > 0;
}

})();
