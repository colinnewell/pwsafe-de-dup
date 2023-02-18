all: pwsafe

pwsafe: cli/main.go pwsafe.go
		go build -o pwsafe cli/main.go

lint:
	golangci-lint run

test:
	go test

fuzz:
	go get github.com/dvyukov/go-fuzz/go-fuzz github.com/dvyukov/go-fuzz/go-fuzz-build
	go-fuzz-build
	go-fuzz
