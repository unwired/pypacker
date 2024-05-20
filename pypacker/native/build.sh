#!/bin/bash
FILE_OBJECT="checksum_native_x86_64.o"
gcc -fPIC -c checksum_native.c -o $FILE_OBJECT
gcc -shared -ochecksum_native_x86_64.so $FILE_OBJECT
rm $FILE_OBJECT
strip checksum_native_x86_64.so
