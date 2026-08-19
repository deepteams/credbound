.PHONY: coverage generate lint test verify

test:
	go test ./...

lint:
	go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.12.2 run

coverage:
	./scripts/coverage.sh

generate:
	go run github.com/sqlc-dev/sqlc/cmd/sqlc@v1.31.1 generate
	go run ./internal/cmd/genevents

verify: generate
	@test -z "$$(rg --files -g '*.go' -0 | xargs -0 gofmt -l)"
	go vet ./...
	go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.12.2 run
	go test -race ./...
	./scripts/coverage.sh
