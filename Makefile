.PHONY: coverage generate test verify

test:
	go test ./...

coverage:
	./scripts/coverage.sh

generate:
	go run github.com/sqlc-dev/sqlc/cmd/sqlc@v1.31.1 generate
	go run ./internal/cmd/genevents
	go run ./internal/cmd/genpostgresstore

verify: generate
	@test -z "$$(rg --files -g '*.go' -0 | xargs -0 gofmt -l)"
	go vet ./...
	go test -race ./...
	./scripts/coverage.sh
