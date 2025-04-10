(Adapted) SHA2 reference implementation in C from https://datatracker.ietf.org/doc/html/rfc6234.

Besides the original code, this repo contains refactored standalone single-file implementations of each algorithm in the following files:
- `standalone-sha1.c`
- `standalone-sha256.c`
- `standalone-sha512.c`

- Build everything (original code as well as single-file implementations):

    ```
    $ ./build.sh
    + CFLAGS='-Wall -Wextra -g'
    + gcc -Wall -Wextra -g -c hkdf.c
    + gcc -Wall -Wextra -g -c hmac.c
    + gcc -Wall -Wextra -g -c sha1.c
    + gcc -Wall -Wextra -g -c sha224-256.c
    + gcc -Wall -Wextra -g -c sha384-512.c
    + gcc -Wall -Wextra -g -c usha.c
    + gcc -g -c shatest.c
    + gcc -Wall -Wextra -g -o shatest hkdf.o hmac.o sha1.o sha224-256.o sha384-512.o shatest.o usha.o
    + gcc -Wall -Wextra -g -o standalone-sha1 standalone-sha1.c
    + gcc -Wall -Wextra -g -o standalone-sha256 standalone-sha256.c
    + gcc -Wall -Wextra -g -o standalone-sha512 standalone-sha512.c
    ```

- Example usage of single-file implementation:

    ```
    $ printf "" | tee >(./standalone-sha1 -) >(sha1sum) >/dev/null
    da39a3ee5e6b4b0d3255bfef95601890afd80709  -
    da39a3ee5e6b4b0d3255bfef95601890afd80709
    $ printf "%2048d" 1 | tee >(./standalone-sha1 -) >(sha1sum) >/dev/null | cat
    a0fde287c73964a70447d4aec6d252ae01a3d7d5  -
    a0fde287c73964a70447d4aec6d252ae01a3d7d5

    $ printf "" | tee >(./standalone-sha256 -) >(sha256sum) >/dev/null | cat
    e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  -
    e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
    $ printf "%2048d" 1 | tee >(./standalone-sha256 -) >(sha256sum) >/dev/null | cat
    e6bc497ab54ccd0a9951871a7fae5ecfa5262c268a40b6205c861307c7e5f637  -
    e6bc497ab54ccd0a9951871a7fae5ecfa5262c268a40b6205c861307c7e5f637

    $ printf "" | tee >(./standalone-sha512 -) >(sha512sum) >/dev/null | cat
    cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e  -
    cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e
    $ printf "%2048d" 1 | tee >(./standalone-sha512 -) >(sha512sum) >/dev/null | cat
    49bcd9e3ae6798129a1302188321555af73ea2eacb989a4b1414d97de65c8d2fc195fe5455c38cb3343e86fcc61f5778bca066e1482d3171867138aeb850f06e  -
    49bcd9e3ae6798129a1302188321555af73ea2eacb989a4b1414d97de65c8d2fc195fe5455c38cb3343e86fcc61f5778bca066e1482d3171867138aeb850f06e
    ```
