-include .env
export

.PHONY: run build test test-e2e migrate-up migrate-down migrate-test

run:            ## start the service (reads .env)
	go run ./cmd/auth-service

build:
	go build -o bin/auth-service ./cmd/auth-service

test:           ## unit tests (no database)
	go test ./...

# Black-box suite over HTTP (positive, negative, security, stress): the real handlers and TEST_DATABASE_URL, a fake
# Portal Master and a clock the tests move. Resets the test database before and after.
test-e2e: migrate-test
	go test -tags e2e -count=1 -v ./test/e2e/

migrate-up:
	migrate -path migrations -database "$(DATABASE_URL)" up

migrate-down:   ## roll back the last migration
	migrate -path migrations -database "$(DATABASE_URL)" down 1

migrate-test:
	migrate -path migrations -database "$(TEST_DATABASE_URL)" up
