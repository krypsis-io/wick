.PHONY: build test lint coverage clean

build:
	CGO_ENABLED=0 go build -o wick ./cmd/wick

test:
	go test -race ./...

lint:
	golangci-lint run --timeout=5m

coverage:
	go test -race -coverprofile=coverage.out -covermode=atomic ./...
	go tool cover -html=coverage.out -o coverage.html

clean:
	rm -f wick coverage.out coverage.html
