all: pwsafe

pwsafe: cli/main.go pwsafe.go
		go build -o pwsafe cli/main.go

lint:
	golangci-lint run
	golint ./...

test:
	go test

fuzz:
	go get github.com/dvyukov/go-fuzz/go-fuzz github.com/dvyukov/go-fuzz/go-fuzz-build
	go-fuzz-build
	go-fuzz
