Squeakspace
===========


What is this?
-------------

Squeakspace is a social media application with end to end encryption.
It lets you send messages to people and make posts that can be seen by groups
of people. Posts can contain text and attached files, such as images and small movies.
Other types of interaction, like instant messaging and video chat are not addressed.
All communication is encrypted using keys that belong to other users,
so the squeakspace servers only see metadata. I was using gpg as the encryption engine
but due to interfacing issues I moved on to a simple scheme with RSA and AES using pyCrypto.


Is it secure?
-------------

Probably not. I would appreciate peer review if
this is your area and you wouldn't mind looking over the source.
All the crypto is in ``lib/squeakspace/common/crypt_squeak.py``.
`lib/squeakspace/common/crypt_gnupg.py`` is a wrapper around gpg
but it has some issues and I plan to abandon it. 
This project now has enough functionality to be used, but it is still
very alpha. If you do decide to test it at this stage, use
it with the expectation that it is not secure.


How does it work?
-----------------

There are servers, which I call nodes, and clients.
The nodes are JSON servers and only communicate with clients.
At this time, nodes are isolated and do not communicate with
one another. The role of a node is to provide cloud storage
for clients. Nodes store an inbox for users, and users can
also create Groups on a node. A Group is an allocated
space on a node for people to make encrypted postings using
a shared key. Only users that have the group keys
can read and write to the group. Users invite each other
to groups by sending the shared group key in a message.


The client runs a local web server on the user's machine,
and the user accesses it by directing their web browser
to ``localhost:12323``. Static html containing javascript is loaded,
and the javascript makes ajax requests to the local web server.
Here's a diagram:


User   <-->   Static HTML with Javascript   <-->   Local Web Server   <-->   Node


The Node handles storing and retrieving encrypted data, as well as spam prevention
using blacklists and hashcash. The Local Web Server manages
all the cryptography. It stores the user's public and private keys in a local database.
It keeps an address book of contacts and their public keys, groups
that the user has access to, and addresses of nodes.
The HTML and javascript application does not handle any cryptography.
Information is passed through the Local Web Server and the necessary
cryptographic operations are applied as it goes through.


How do users authenticate each other?
-------------------------------------

You need to verify your public key hashes
either in person or through a reliable channel.
Soon there will be a way for users to sign each other's keys
and post the signatures on a group that is readable by their friends.
Then there will be a friend to friend web of trust. Users can
do this manually right now by exporting their contacts and posting
signed messages containing the JSON export, but I'll make it easier soon.


What is it written in?
----------------------

The servers are written in python and use WSGI.
I didn't use any framework. Since the servers only generate
JSON and serve static files, it didn't seem necessary.
I've been using `apache2 <https://httpd.apache.org/>`_ with
`mod_wsgi <https://modwsgi.readthedocs.io/en/develop/>`_. 
I incorporated `cherrypy <http://cherrypy.org/>`_ as an alternative
minimal web server for the local client. Both servers
use sqlite3 for their database.



How do I use it?
----------------

I have only tested on Linux so far but it is portable in theory:

* Clone this repository or download it as a zip file using
  the button at the top of this page. 
* Read the ``instructions.txt`` file under the install directory
  for your platform. It will tell you to install a recent
  version of `python 2.7 <https://www.python.org/download/releases/2.7/>`_,
  and to run a script that will install the needed python libraries.
* Now to run the client, run or click on ``launch_client.py`` at
  the root of the repository. This script will start the local
  web server proxy using cherrypy if it isn't already running and open
  ``http://localhost:12323`` in a webbrowser.
  Click the ``sq/space`` link to get to the more
  usable version of the site and sign up. You'll need the name and server
  address of a node to create an account on. 
  I haven't set up a node yet, but once I do I'll post the info here.


If you can install `apache <https://httpd.apache.org/>`_, the client also
runs on that using `mod_wsgi <https://modwsgi.readthedocs.io/en/develop/>`_.
See ``doc/proxy_config.tt`` for help creating the apache configuration file.


How do I run a node?
--------------------

It's possible to use the instructions above and run the node with cherrypy
by executing the script ``config/cherrypy/server/server.py`` but I don't
recommend this, since the node faces the outside internet.

* Install `apache <https://httpd.apache.org/>`_ and 
  `mod_wsgi <https://modwsgi.readthedocs.io/en/develop/>`_.
* Create the apache config file for the node site using
  ``doc/server_config.tt``.
* Edit ``config/server/config.py``. Set ``node_name``
  to a name that should be unique if possible.
  Set ``total_quota`` to the amount of space you'd like to provide.
  Set ``max_user_quota`` to the maximum amount of space a user
  can have. 


Things to do
------------

* Make a one-click installation process
* Make the site look better
* Get a node running so people can start testing it out
* Security code review


Contact
-------

Github thinks my browser is a spambot, so I don't log in here.
You can email me at eek@safe-mail.net. I am also eek6 at reddit.

