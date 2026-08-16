BINARY := ordeal
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X github.com/principlebreach/ordeal/internal/cli.version=$(VERSION)

.PHONY: build test vet lint fmt cover run demo clean

build:
	go build -ldflags "$(LDFLAGS)" -o $(BINARY) ./cmd/ordeal

test:
	go test ./...

vet:
	go vet ./...

fmt:
	gofmt -s -w .

cover:
	go test -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out | tail -1

# Assert the example rules fire on their fixtures.
run: build
	./$(BINARY) run ./examples

# Attack the example rules and show what slips past.
demo: build
	./$(BINARY) mutate ./examples

clean:
	rm -f $(BINARY) coverage.out coverage.html
	rm -rf dist/
