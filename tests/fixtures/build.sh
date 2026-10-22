#!/bin/sh
# Rebuilds the test binaries from sample.c (needs Apple clang).
set -e
cd "$(dirname "$0")"
clang -O1 -arch arm64 -arch x86_64 -o sample_macho sample.c
clang -O1 -target x86_64-linux-gnu -c -o sample_elf.o sample.c
clang -O1 -arch arm64 -arch x86_64 -fobjc-arc -framework Foundation -o sample_objc sample_objc.m
strip -x -o sample_objc_stripped sample_objc
clang -O2 -arch arm64 -arch x86_64 -o sample_cfg sample_cfg.c
