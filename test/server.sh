#!/usr/bin/env sh

openssl s_server -cert cert.pem -key key.pem -accept localhost:8443 -tls1_3
