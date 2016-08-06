// accessselect.js
// allow, block, proof_of_work/{args...}

(function () {


/*
   ui = {access_select,
         say,
         proof_of_work: {div,
                         alg_select,
                         dummy: {div, level_input},
                         hashcash: {div,
                                    bits_input,
                                    saltchars_input}}}
 */
AccessSelect = function(ui) {
    this.ui = ui;
}


AccessSelect.defaultUI = function(div) {

    var message = div.find('.message'),
        say = function(mesg) {
            message.text(mesg);
        };

    message.click(function() {message.text('');});

    var message_access = new AccessSelect(
            {access_select: div.find('.access-select'),
             say: say,
             proof_of_work: {div: div.find('.pow-div'),
                             alg_select: div.find('.pow-alg-select'),
                             dummy: {div: div.find('.dummy-div'),
                                     level_input: div.find('.dummy-level')},
                             hashcash: {div: div.find('.hashcash-div'),
                                        bits_input: div.find('.hashcash-bits'),
                                        saltchars_input: div.find('.hashcash-saltchars')}}});

    return message_access;
}

AccessSelect.prototype.initUI = function() {
    var self = this;

    this.ui.access_select
        .append($('<option>'))
        .append($('<option>').val('allow').append('Allow'))
        .append($('<option>').val('block').append('Block'))
        .append($('<option>').val('proof_of_work').append('Proof of Work'))
        .change(function() {
                    self.accessSelectChange();
                });

    this.ui.proof_of_work.alg_select
        .append($('<option>'))
        // .append($('<option>').val('dummy').append('Dummy')) // Only allow dummy proof of work when debugging.
        .append($('<option>').val('hashcash').append('Hashcash'))
        .change(function() {
                    self.algSelectChange();
                });
}

AccessSelect.prototype.accessSelectChange = function() {
    if (this.ui.access_select.val() === 'proof_of_work') {
        this.ui.proof_of_work.div.show();
    } else {
        this.ui.proof_of_work.div.hide();
    }
}

AccessSelect.prototype.algSelectChange = function() {
    var alg = this.ui.proof_of_work.alg_select.val();

    if (alg === 'dummy') {
        this.ui.proof_of_work.dummy.div.show();
        this.ui.proof_of_work.hashcash.div.hide();
    } else if (alg === 'hashcash') {
        this.ui.proof_of_work.dummy.div.hide();
        this.ui.proof_of_work.hashcash.div.show();
    } else {
        this.ui.proof_of_work.dummy.div.hide();
        this.ui.proof_of_work.hashcash.div.hide();
    }
}

AccessSelect.prototype.value = function() {
    var access = this.ui.access_select.val();

    if (access === 'proof_of_work') {
        var alg = this.ui.proof_of_work.alg_select.val(),
            args = {algorithm: alg};

        if (alg === 'dummy') {
            var level_text = this.ui.proof_of_work.dummy.level_input.val(),
                level = parseInt(level_text);
            
            if (isNaN(level)) {
                this.ui.say('level must be an integer');
            }

            args.level = level;
        } else if (alg === 'hashcash') {
            var bits_text = this.ui.proof_of_work.hashcash.bits_input.val(),
                saltchars_text = this.ui.proof_of_work.hashcash.saltchars_input.val(),
                bits = parseInt(bits_text),
                saltchars = parseInt(saltchars_text);

            if (isNaN(bits)) {
                this.ui.say('bits must be an integer');
                return null;
            }

            if (isNaN(saltchars)) {
                this.ui.say('saltchars must be an integer');
                return null;
            }

            args.bits = bits;
            args.saltchars = saltchars;
        } else {
            this.ui.say('Select an algorithm');
            return null;
        }

        return 'proof_of_work/' + JSON.stringify(args);

    } else {
        return access;
    }
}

})();
