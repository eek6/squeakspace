// passphrasedialog.js
//
// controls a dialog that prompts for passphrases for keys
// there is one dialog and it will request passphrases for multiple keys.
// each key has a queue of pending events waiting for the passphrase.

(function() {

/*
   ui = {div,
         say,
         key_purpose_span,
         public_key_hash_span,
         passphrase_input,
         cache_period_input,
         handle_error}
   */
PassphraseDialog = function(ui) {
    this.ui = ui;
    this.public_key_hash = null;
    this.key_map = {};
}


PassphraseDialog.defaultUi = function(div, handle_error) {
    var message = div.find('.message'),
        say = function(mesg) {
            message.text(mesg);
        },
   pass_dialog = new PassphraseDialog(
           {div: div,
            say: say,
            key_purpose_span: div.find('.key-purpose'),
            public_key_hash_span: div.find('.public-key-hash'),
            passphrase_input: div.find('.passphrase'),
            cache_period_input: div.find('.cache-period'),
            enter_button: div.find('.enter'),
            handle_error: handle_error});

   message.click(function(){say('');});

   return pass_dialog;
}

PassphraseDialog.prototype.initUi = function() {
    var this_ = this;

    this.ui.enter_button.click(
            function() {
                this_.submit();
            });
}

PassphraseDialog.prototype.prompt = function(key_purpose, public_key_hash) {
    this.public_key_hash = public_key_hash;
    this.ui.key_purpose_span.text(key_purpose);
    this.ui.public_key_hash_span.text(public_key_hash);
    this.ui.passphrase_input.val('');
    this.ui.cache_period_input.val('');
    this.ui.div.show();
}

PassphraseDialog.prototype.submit = function() {
    var this_ = this,
        public_key_hash = this_.public_key_hash,
        passphrase = this_.ui.passphrase_input.val(),
        cache_delay_text = this_.ui.cache_period_input.val(),
        now = Date.now(),
        expire_time = '';

        //alert('submit: ' + JSON.stringify([public_key_hash, passphrase, cache_delay_text, now]));

        if (cache_delay_text !== '') {
            var cache_delay = parseInt(cache_delay_text);

            if (isNaN(cache_delay)) {
                this.ui.say('Invalid cache delay');
                return;
            }

            expire_time = now + cache_delay*60*1000;
        } 

        //alert('expire_time: ' + expire_time);

        squeakclient.local.cache_passphrase(
                {public_key_hash: public_key_hash,
                 passphrase: passphrase,
                 expire_time: expire_time},
                function(resp, textStatus) {
                    debug(JSON.stringify(resp));
                    //alert(JSON.stringify(resp));
    
                    if (resp.status === 'ok') {

                        //alert('before anything: ' + JSON.stringify(this_.key_map));
                        var task_queue = this_.key_map[public_key_hash][1];

                        //alert('before delete: ' + JSON.stringify(this_.key_map));
                        delete this_.key_map[public_key_hash];
                        //alert('after delete: ' + JSON.stringify(this_.key_map));

                        var keys = Object.keys(this_.key_map);


                        if (keys.length === 0) {
                            this_.ui.div.hide();
                        } else {
                            var hash = keys[0],
                                purpose = this_.key_map[hash][0];
                            this_.prompt(purpose, hash);
                        }

                        task_queue.execute();

                    } else if (resp.status === 'error') {
                        this_.ui.handle_error(resp, this_.say);
                    } else {
                    }
                });
}

PassphraseDialog.prototype.enqueue = function(key_purpose, pkh, task) {
    if (Object.keys(this.key_map).length === 0) {
        this.key_map[pkh] = [key_purpose, new TaskQueue([task])];
        this.prompt(key_purpose, pkh)
    } else {
        var data = this.key_map[pkh];
        if (data === undefined) {
            this.key_map[pkh] = [key_purpose, new TaskQueue([task])];
        } else {
            this.key_map[pkh][1].append(task);
        }
    }
}

})();
