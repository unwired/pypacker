#!/bin/bash
gcc -fPIC -c checksum_native.c -o checksum_native_x86_64.o
gcc -shared -ochecksum_native_x86_64.so checksum_native_x86_64.o
strip checksum_native_x86_64.so
