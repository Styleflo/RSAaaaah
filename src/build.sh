#!/bin/bash
gcc serveur.c -o serveur \
    -I/opt/homebrew/opt/openssl@3/include \
    -L/opt/homebrew/opt/openssl@3/lib \
    -lssl -lcrypto
