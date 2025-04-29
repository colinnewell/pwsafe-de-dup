all: pwsafe test

pwsafe: cli/main.go pwsafe.go go.*
		go build -o pwsafe cli/main.go

lint:
	golangci-lint run

test: cli/main.go pwsafe.go go.*
	go test

fuzz:
	go get github.com/dvyukov/go-fuzz/go-fuzz github.com/dvyukov/go-fuzz/go-fuzz-build
	go-fuzz-build
	go-fuzz
