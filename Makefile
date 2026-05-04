.PHONY: build test vet lint fmt complexity security tidy ci clean all check-fixtures

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS = -s -w -X main.version=$(VERSION)
BIN ?= policyguard

build:
	go build -ldflags "$(LDFLAGS)" -o $(BIN) ./cmd/policyguard/

test:
	go test ./... -count=1

vet:
	go vet ./...

fmt:
	gofmt -s -w .

lint:
	golangci-lint run

complexity:
	gocyclo -over 12 -ignore '_test\.go$$' .

security:
	gosec -exclude=G104,G304,G703 ./...

tidy:
	go mod tidy

ci: vet test complexity lint security

clean:
	rm -f $(BIN) junit-report.xml gosec-report.xml

all: build vet test

check-fixtures: build
	BIN=./$(BIN) bash scripts/check-fixtures.sh
