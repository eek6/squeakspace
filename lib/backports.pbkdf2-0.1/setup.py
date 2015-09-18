#!/usr/bin/env python
from distutils.core import setup, Extension
from distutils.command.build_ext import build_ext
import logging

class OptionalBuildExt(build_ext):
    def run(self):
        try:
            build_ext.run(self)
        except Exception:
            logging.basicConfig()
            logging.exception("Failed to compile optional C extension")


long_description = []
with open('README.txt') as f:
    long_description.append(f.read())
with open('CHANGES.txt') as f:
    long_description.append(f.read())

setup(
    name='backports.pbkdf2',
    version='0.1',
    ext_modules= [Extension('backports.pbkdf2._pbkdf2',
                            ['backports/pbkdf2/_pbkdf2.c'],
                            libraries = ['ssl', 'crypto'])],
    cmdclass={"build_ext": OptionalBuildExt},
    packages=['backports.pbkdf2'],
    namespace_packages=['backports'],
    author='Christian Heimes',
    author_email='christian@python.org',
    maintainer='Christian Heimes',
    maintainer_email='christian@python.org',
    url='https://bitbucket.org/tiran/backports.pbkdf2',
    keywords='pbkdf2 password openssl security',
    platforms='POSIX, Windows',
    license='PSFL',
    description='Fast PBKDF2 for Python 2.6 - 3.4',
    long_description='\n'.join(long_description),
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: Python Software Foundation License',
        'Natural Language :: English',
        'Operating System :: POSIX',
        'Operating System :: Microsoft :: Windows',
        'Programming Language :: C',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.6',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.2',
        'Programming Language :: Python :: 3.3',
        # 'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: Implementation :: CPython',
        'Programming Language :: Python :: Implementation :: PyPy',
        'Topic :: Security :: Cryptography',
    ],
)

