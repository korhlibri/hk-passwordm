#!/bin/bash

# rm ./target/release/libhk_passwordm.a
# rm ./src/link.o
rm ./app

cargo build --lib --release

gcc -c -o ./src/link.o ./src/link.c
# ar rcs ./target/release/libhk_passwordm.a ./src/link.o

go build -o app ./src/main.go