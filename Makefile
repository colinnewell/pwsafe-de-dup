all: pwsafe

pwsafe: cli/main.go pwsafe.go
		go build -o pwsafe cli/main.go

lint:
	golangci-lint run
	golint ./...
