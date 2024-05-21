#!/bin/bash

rm ./app

(cargo build --lib --release | exit 1)

# go build -o app ./src/main.go
go build -o app -ldflags "-s -w" ./src/main.go