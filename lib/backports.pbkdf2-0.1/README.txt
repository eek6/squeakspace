========================================================
PKCS#5 password-based key derivation function 2 (PBKDF2)
========================================================

This is a backport of ``hashlib.pbkdf2_hmac`` for Python 2.6 to 2.7. The
implementation comes with a pure Python implementation and a C module that
depends on OpenSSL. The C code does *not* wrap ``PKCS5_PBKDF2_HMAC`` as
its implementation is suboptimal.


Usage
=====

::

  >>> from backports.pbkdf2 import pbkdf2_hmac, compare_digest
  >>> dkey = pbkdf2_hmac('sha1', passwordbytes, saltbytes, iterations=100000)
  >>> compare_digest(dkey, originalkey)
  True


pbkdf2_hmac(hash_name, password, salt, iterations, dklen=None)

  hash_name
    name of the digest algorithm as string

  password
    password as bytes, bytearray or bytes-like object (*)

  salt
    salt as bytes, bytearray or bytes-like object (*). The salt should be
    generated with a CPRNG like ``os.urandom()``. You should **never** use
    ``random.random()``. About 16 bytes seem to be a good choice.

  iterations
    number of rounds, 100,000 rounds of SHA-1 take about 30ms on a modern
    CPU.

  dklen
    length of the derived key (defaults to digest_size)

  returns
    derived key as bytes

  (*) bytearray and bytes-like objects are not supported on Python 2.6


Benchmarks
==========

====================   =====   =====   =====   ======
password length           10     100     500     1000
====================   =====   =====   =====   ======
backports.pbkdf2 C     0.314   0.321   0.310    0.310
backports.pbkdf2 Py    0.838   0.847   0.853    0.913
pbkdf2_ctypes 0.99.3   0.554   0.663   0.954    1.344
pbkdf2 1.3             5.235   5.746   6.155    6.450
Django pbkdf2 1.5.4    1.976   2.430   2.676    3.078
PyCrypto 2.6.1         6.903   9.062   9.518   10.274
====================   =====   =====   =====   ======

  algorithm
    sha1
  rounds
    50000
  dklen
    20
  saltlen
    16
  number of runs per test
    10
  Python
    Python 3.3 on Linux AMD64
  CPU
    Intel i7-2860QM @ 2.50GHz
