VERSION?=$(shell git symbolic-ref -q --short HEAD || git describe --tags --exact-match)
COMPILEDATE=$(shell date +"%Y-%m-%d")
all:*.go
	rm -f check_abuseipdb-*
	env GOOS=darwin GOARCH=amd64 go build -ldflags "-s -w -X main.version=$(VERSION) -X main.compileDate=$(COMPILEDATE)" -o check_abuseipdb-darwin-amd64
	env GOOS=freebsd GOARCH=amd64 go build -ldflags "-s -w -X main.version=$(VERSION) -X main.compileDate=$(COMPILEDATE)" -o check_abuseipdb-freebsd-amd64
	env GOOS=linux GOARCH=amd64 go build -ldflags "-s -w -X main.version=$(VERSION) -X main.compileDate=$(COMPILEDATE)" -o check_abuseipdb-linux-amd64

dev:*.go
	rm -f check_abuseipdb
	go build -o check_abuseipdb