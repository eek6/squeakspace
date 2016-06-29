import threading

class PassphraseCache:

    def __init__(self):
        # print "PassphraseCache: init"
        self.lock = threading.Lock()
        self.cache = {}

    def set(self, user, public_key_hash, passphrase, expire_time):
        # print "PassphraseCache: set(%s, %s, -----, %s)" % (user, public_key_hash, expire_time)
        self.lock.acquire()

        if self.cache.get(user) == None:
            self.cache[user] = {}

        self.cache[user][public_key_hash] = (passphrase, expire_time)

        self.lock.release()

    def get(self, user, public_key_hash):
        # print "PassphraseCache: get(%s, %s)" % (user, public_key_hash)
        self.lock.acquire()

        try:
            return self.cache[user][public_key_hash]
        except KeyError:
            return None

        finally:
            self.lock.release()

    def get_passphrase(self, user, public_key_hash):
        row = self.get(user, public_key_hash)

        # print "PassphraseCache: got_passphrase(%s, %s, %s)" % (user, public_key_hash, row)

        if row == None:
            return None
        else:
            return row[0]

    def delete(self, user, public_key_hash):
        # print "PassphraseCache: delete(%s, %s)" % (user, public_key_hash)
        self.lock.acquire()

        try:
            del self.cache[user][public_key_hash]
        except KeyError:
            pass

        self.lock.release()

    def purge_expired(self, clip_time):
        self.lock.acquire()

        for user in self.cache:
            for public_key_hash in self.cache[user]:
                (passphrase, expire_time) = self.cache[user][public_key_hash]

                if expire_time != None and expire_time <= clip_time:
                    del self.cache[user][public_key_hash]

        self.lock.release()

    def purge_user(self, user):
        self.lock.acquire()

        try:
            del self.cache[user]
        except KeyError:
            pass

        self.lock.release()


        



