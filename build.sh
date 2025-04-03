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
