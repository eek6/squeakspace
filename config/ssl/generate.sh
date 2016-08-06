#!/bin/sh

openssl req -x509 -nodes -newkey rsa:4096 -keyout key.pem -out selfcert.crt
