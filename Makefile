.PHONY: build test test-unit test-integration lint vet vuln image ci

build:
	go build -o bin/fit-issuer ./cmd/fit-issuer

test: test-unit test-integration

test-unit:
	go test ./internal/... -race -count=1 -v

test-integration:
	go test ./tests/integration/... -count=1 -v -timeout 60s

lint:
	@which golangci-lint >/dev/null 2>&1 || \
		curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/HEAD/install.sh | \
		sh -s -- -b $$(go env GOPATH)/bin
	$$(go env GOPATH)/bin/golangci-lint run ./...

vet:
	go vet ./...

vuln:
	govulncheck ./...

image:
	podman build -t fit-issuer:local .

ci: lint vet test
