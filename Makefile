GO_VERSION := 1.26.5
GOLANGCI_LINT_VERSION := latest

ifeq ($(shell command -v go 2>/dev/null),)
DOCKER_GO := docker run --rm -e GOFLAGS=-buildvcs=false -v "$(CURDIR)":/src -w /src golang:$(GO_VERSION)
DOCKER_LINT := docker run --rm -v "$(CURDIR)":/src -w /src golangci/golangci-lint:$(GOLANGCI_LINT_VERSION)
else
DOCKER_GO :=
DOCKER_LINT :=
endif


.PHONY: fmt build test bench lint

fmt:
	$(DOCKER_GO) go fmt ./...

build:
	$(DOCKER_GO) go build -o dist/authzmtls ./cmd/authzmtls

test:
	$(DOCKER_GO) go test ./...

bench:
	$(DOCKER_GO) go test ./... -run '^$$' -bench . -benchmem

lint:
	$(DOCKER_LINT) golangci-lint run
