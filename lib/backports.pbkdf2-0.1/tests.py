# -*- coding: utf-8 -*-
from __future__ import unicode_literals
import sys
import unittest
import platform
from backports.pbkdf2 import py_pbkdf2_hmac, pbkdf2_hmac, compare_digest

try:
    from backports.pbkdf2._pbkdf2 import pbkdf2_hmac as c_pbkdf2_hmac
except ImportError:
    c_pbkdf2_hmac = None


if sys.version_info[0] == 3:
    PY3 = True
    fromhex = bytes.fromhex
else:
    PY3 = False
    fromhex = lambda s: s.decode("hex")

if sys.version_info < (2, 7):
    PY26 = True
    memoryview = buffer

    def _id(obj):
        return obj

    def _skip(obj):
        return lambda self: None

    def skipUnless(condition, reason):
        return _id if condition else _skip

    def skipIf(condition, reason):
        return _skip if condition else _id
else:
    PY26 = False
    skipUnless = unittest.skipUnless
    skipIf = unittest.skipIf

implementation = platform.python_implementation().lower()


def cpython_only(func):
    return skipUnless(implementation == "cpython", "cpython only")(func)


class PBKDF2Tests(unittest.TestCase):
    pbkdf2_test_vectors = [
        (b'password', b'salt', 1, None),
        (b'password', b'salt', 2, None),
        (b'password', b'salt', 4096, None),
        # too slow, it takes over a minute on a fast CPU.
        #(b'password', b'salt', 16777216, None),
        (b'passwordPASSWORDpassword', b'saltSALTsaltSALTsaltSALTsaltSALTsalt',
         4096, -1),
        (b'pass\0word', b'sa\0lt', 4096, 16),
    ]

    pbkdf2_results = {
        "sha1": [
            # offical test vectors from RFC 6070
            (fromhex('0c60c80f961f0e71f3a9b524af6012062fe037a6'), None),
            (fromhex('ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957'), None),
            (fromhex('4b007901b765489abead49d926f721d065a429c1'), None),
            #(fromhex('eefe3d61cd4da4e4e9945b3d6ba2158c2634e984'), None),
            (fromhex('3d2eec4fe41c849b80c8d83662c0e44a8b291a964c'
                     'f2f07038'), 25),
            (fromhex('56fa6aa75548099dcc37d7f03425e0c3'), None)],
        "sha256": [
            (fromhex('120fb6cffcf8b32c43e7225256c4f837'
                     'a86548c92ccc35480805987cb70be17b'), None),
            (fromhex('ae4d0c95af6b46d32d0adff928f06dd0'
                     '2a303f8ef3c251dfd6e2d85a95474c43'), None),
            (fromhex('c5e478d59288c841aa530db6845c4c8d'
                     '962893a001ce4e11a4963873aa98134a'), None),
            #(fromhex('cf81c66fe8cfc04d1f31ecb65dab4089'
            #               'f7f179e89b3b0bcb17ad10e3ac6eba46'), None),
            (fromhex('348c89dbcbd32b2f32d814b8116e84cf2b17'
                     '347ebc1800181c4e2a1fb8dd53e1c635518c7dac47e9'), 40),
            (fromhex('89b69d0516f829893c696226650a8687'), None)],
        "sha512": [
            (fromhex('867f70cf1ade02cff3752599a3a53dc4af34c7a669815ae5'
                     'd513554e1c8cf252c02d470a285a0501bad999bfe943c08f'
                     '050235d7d68b1da55e63f73b60a57fce'), None),
            (fromhex('e1d9c16aa681708a45f5c7c4e215ceb66e011a2e9f004071'
                     '3f18aefdb866d53cf76cab2868a39b9f7840edce4fef5a82'
                     'be67335c77a6068e04112754f27ccf4e'), None),
            (fromhex('d197b1b33db0143e018b12f3d1d1479e6cdebdcc97c5c0f8'
                     '7f6902e072f457b5143f30602641b3d55cd335988cb36b84'
                     '376060ecd532e039b742a239434af2d5'), None),
            (fromhex('8c0511f4c6e597c6ac6315d8f0362e225f3c501495ba23b8'
                     '68c005174dc4ee71115b59f9e60cd9532fa33e0f75aefe30'
                     '225c583a186cd82bd4daea9724a3d3b8'), 64),
            (fromhex('9d9e9c4cd21fe4be24d5b8244c759665'), None)],
    }

    def _test_pbkdf2_hmac(self, pbkdf2):
        for digest_name, results in self.pbkdf2_results.items():
            for i, vector in enumerate(self.pbkdf2_test_vectors):
                password, salt, rounds, dklen = vector
                expected, overwrite_dklen = results[i]
                if overwrite_dklen:
                    dklen = overwrite_dklen
                out = pbkdf2(digest_name, password, salt, rounds, dklen)
                self.assertEqual(out, expected,
                                 (digest_name, password, salt, rounds, dklen))
                if not PY26:
                    out = pbkdf2(digest_name, memoryview(password),
                                 memoryview(salt), rounds, dklen)
                    self.assertEqual(out, expected,
                                     (digest_name, password, salt, rounds))
                    out = pbkdf2(digest_name, bytearray(password),
                                 bytearray(salt), rounds, dklen)
                    self.assertEqual(out, expected,
                                     (digest_name, password, salt, rounds))
                if dklen is None:
                    out = pbkdf2(digest_name, password, salt, rounds)
                    self.assertEqual(out, expected,
                                     (digest_name, password, salt, rounds))

        if PY3:
            self.assertRaises(TypeError, pbkdf2, b'sha1', b'pass', b'salt', 1)
            self.assertRaises(TypeError, pbkdf2, 'sha1', 'pass', 'salt', 1)
        self.assertRaises(ValueError, pbkdf2, 'sha1', b'pass', b'salt', 0)
        self.assertRaises(ValueError, pbkdf2, 'sha1', b'pass', b'salt', -1)
        self.assertRaises(ValueError, pbkdf2, 'sha1', b'pass', b'salt', 1, 0)
        self.assertRaises(ValueError, pbkdf2, 'sha1', b'pass', b'salt', 1, -1)
        self.assertRaises(ValueError, pbkdf2, 'unknown', b'pass', b'salt', 1)

    def test_py_pbkdf2(self):
        self._test_pbkdf2_hmac(py_pbkdf2_hmac)

    @cpython_only
    def test_c_pbkdf2(self):
        self._test_pbkdf2_hmac(c_pbkdf2_hmac)

    @cpython_only
    def test_pbkdf2_hmac_func(self):
        if sys.version_info < (2, 7):
            self.assertTrue(pbkdf2_hmac is pbkdf2_hmac)
        else:
            self.assertIs(pbkdf2_hmac, pbkdf2_hmac)

    def test_compare_digest(self):
        self.assertTrue(compare_digest('', ''))
        self.assertTrue(compare_digest('a', 'a'))
        self.assertTrue(compare_digest('\x00', '\x00'))
        self.assertFalse(compare_digest('a', 'b'))
        self.assertFalse(compare_digest('', 'a'))
        self.assertFalse(compare_digest('a', ''))

        self.assertTrue(compare_digest(b'', b''))
        self.assertTrue(compare_digest(b'a', b'a'))
        self.assertTrue(compare_digest(b'\x00', b'\x00'))
        self.assertFalse(compare_digest(b'a', b'b'))
        self.assertFalse(compare_digest(b'', b'a'))
        self.assertFalse(compare_digest(b'a', b''))

        self.assertTrue(compare_digest(b'a', bytearray(b'a')))
        self.assertFalse(compare_digest(b'a', bytearray(b'b')))

        self.assertRaises(TypeError, compare_digest, 'a', b'a')
        self.assertRaises(TypeError, compare_digest, 'ä', 'ä')


if __name__ == "__main__":
    unittest.main()
