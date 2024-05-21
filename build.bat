cargo build --lib --release

@REM go build -o app ./src/main.go
go build -o app -ldflags "-s -w" ./src/main.go