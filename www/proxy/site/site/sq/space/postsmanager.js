
(function () {


// methods.load_headers_starting(start_time, max_records, callback) // callback(array)
// methods.load_headers_ending(end_time, max_records, callback) // callback(array)
// methods.load_post(post_header, callback) // callback(post, outer_validation)
// methods.validate_post(post, callback) // callback(inner_validation)
// methods.post_timestamp(post)
// methods.make_block_div(window_div, position) // position = 'start' or 'end'
// methods.publish_post(block_div, post, inner_validation, outer_validation)
// methods.remove_div(div)


PostsBlockManager = function(block_div, start_time, end_time, header_array, order, methods) {
    this.block_div = block_div;
    this.start_time = start_time;
    this.end_time = end_time;
    this.header_array = header_array;
    this.order = order;
    this.methods = methods;
};

PostsBlockManager.prototype.remove = function() {
    this.methods.remove_div(this.block_div);
};

PostsBlockManager.prototype.load_post = function(i, done) {
    var man = this;

    if (0 <= i && i < man.header_array.length) {
        var header = man.header_array[i];

        man.methods.load_post(
                header,
                function(post, outer_validation) {
                    man.methods.validate_post(
                        post,
                        function(inner_validation) {
                            man.methods.publish_post(man.block_div, post, inner_validation, outer_validation);
                            
                            if (man.order === 'asc') {
                                man.load_post(i + 1, done);
                            } else if (man.order === 'desc') {
                                man.load_post(i - 1, done);
                            }
                        });
                });
    } else {
        done();
    }
}

PostsBlockManager.prototype.load_posts = function(done) {
    if (this.order === 'asc') {
        this.load_post(0, done)
    } else if (this.order === 'desc') {
        this.load_post(this.header_array.length - 1, done);
    }
};

PostsWindowManager = function(window_div, initial_time, block_length, methods) {
    this.window_div = window_div;

    this.start_time = initial_time; 
    this.end_time = initial_time; 
    this.block_length = block_length;

    this.methods = methods;

    this.prev_block = null;
    this.curr_block = null;
    this.next_block = null;
};

PostsBlockManager.prototype.debug_obj = function() {
    return {start_time: this.start_time,
            end_time: this.end_time,
            posts: this.header_array.length};
};

PostsWindowManager.prototype.debug_obj = function() {
    return {start_time: this.start_time,
            end_time: this.end_time,
            prev_block: this.prev_block === null ? null : this.prev_block.debug_obj(),
            curr_block: this.curr_block === null ? null : this.curr_block.debug_obj(),
            next_block: this.next_block === null ? null : this.next_block.debug_obj()};
};


// handlers = {done(block) , empty() }
PostsWindowManager.prototype.load_starting_block = function(start_time, handlers) {
    var man = this;

    man.methods.load_headers_starting(
            start_time,
            man.block_length,
            function(header_array) {
                if (header_array.length > 0) {
                    var end_time = man.methods.post_timestamp(header_array[header_array.length - 1]) + 1,
                        block_div = man.methods.make_block_div(man.window_div, 'end'),
                        block_manager = new PostsBlockManager(
                            block_div, start_time, end_time, header_array, 'asc', man.methods);

                    handlers.done(block_manager);
                } else {
                    handlers.empty();
                }
            });
};

// handlers = {done(block) , empty() }
PostsWindowManager.prototype.load_ending_block = function(end_time, handlers) {
    var man = this;

    man.methods.load_headers_ending(
            end_time - 1,
            man.block_length,
            function(header_array) {
                if (header_array.length > 0) {
                    var start_time = man.methods.post_timestamp(header_array[header_array.length - 1]),
                        block_div = man.methods.make_block_div(man.window_div, 'start'),
                        block_manager = new PostsBlockManager(
                            block_div, start_time, end_time, header_array, 'desc', man.methods);

                    handlers.done(block_manager);
                } else {
                    handlers.empty();
                }
            });
};


PostsWindowManager.prototype.adjust_times = function(block) {
    if (this.start_time > block.start_time)
        this.start_time = block.start_time;

    if (this.end_time < block.end_time)
        this.end_time = block.end_time;
};


// handlers = {done(), empty()}
PostsWindowManager.prototype.init = function(direction, handlers) {
    var man = this;

    if (direction === 'forward') {
        man.load_starting_block(
                man.end_time,
                {
                    done: function(new_block) {
                        man.curr_block = new_block;
                        man.adjust_times(new_block);
                        new_block.load_posts(handlers.done);
                    },
                    empty: handlers.empty
                });
    } else if (direction === 'backward') {
        man.load_ending_block(
                man.start_time,
                {
                    done: function(new_block) {
                        man.curr_block = new_block;
                        man.adjust_times(new_block);
                        new_block.load_posts(handlers.done);
                    },
                    empty: handlers.empty
                });
    }
};

// handlers = {done(), empty()}
PostsWindowManager.prototype.load_next_block = function(handlers) {
    var man = this;

    man.load_starting_block(
            man.end_time,
            {
                done: function(new_block) {
                    man.next_block = new_block;
                    man.adjust_times(new_block);
                    new_block.load_posts(handlers.done);
                },
                empty: handlers.empty
            });
};

// handlers = {done(), empty()}
PostsWindowManager.prototype.load_prev_block = function(handlers) {
    var man = this;

    man.load_ending_block(
            man.start_time,
            {
                done: function(new_block) {
                    man.prev_block = new_block;
                    man.adjust_times(new_block);
                    new_block.load_posts(handlers.done);
                },
                empty: handlers.empty
            });
};

// handlers = {done(), empty()}
PostsWindowManager.prototype.shift_blocks_forward = function(handlers) {

    if (this.curr_block !== null) {

        if (this.next_block !== null) {
            var prev_block = this.prev_block;
        
            this.prev_block = this.curr_block;
            this.curr_block = this.next_block;
            this.next_block = null;
        
            this.start_time = this.prev_block.start_time;
        
            if (prev_block !== null)
                prev_block.remove();
        }

        this.load_next_block(handlers);
    } else {
        this.init('forward', handlers);
    }
};

// handlers = {done(), empty()}
PostsWindowManager.prototype.shift_blocks_backward = function(handlers) {

    if (this.curr_block !== null) {

        if (this.prev_block !== null) {
            var next_block = this.next_block;
        
            this.next_block = this.curr_block;
            this.curr_block = this.prev_block;
            this.prev_block = null;
        
            this.end_time = this.next_block.end_time;
        
            if (next_block !== null)
                next_block.remove();
        }

        this.load_prev_block(handlers);
    } else {
        this.init('backward', handlers);
    }
};


})();
