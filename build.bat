cargo build --lib --release

gcc -c -o ./src/link.o ./src/link.c
ar rcs ./target/release/libhk_passworm.a ./src/link.o

go build -o app ./src/main.go