.PHONY: test vet fuzz build fmt

fmt:
	gofmt -w sentiniel.go sentiniel_test.go cmd/sentiniel/main.go

test:
	go test ./...

vet:
	go vet ./...

fuzz:
	go test -fuzz=FuzzDecodeGitHubContent -fuzztime=10s

build:
	go build -o sentiniel ./cmd/sentiniel
