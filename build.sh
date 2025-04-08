#!/bin/bash

set -ex

CFLAGS="-Wall -Wextra -g"

gcc $CFLAGS -c hkdf.c
gcc $CFLAGS -c hmac.c
gcc $CFLAGS -c sha1.c
gcc $CFLAGS -c sha224-256.c
gcc $CFLAGS -c sha384-512.c
gcc $CFLAGS -c usha.c

gcc -g -c shatest.c

gcc $CFLAGS -o shatest *.o

gcc $CFLAGS -o standalone-sha1   standalone-sha1.c
gcc $CFLAGS -o standalone-sha256 standalone-sha256.c
