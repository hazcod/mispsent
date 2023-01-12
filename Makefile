
all: run

build:
	go build -o mispsent ./cmd/...

run:
	go run ./cmd/... -config=dev.yml

test:
	go test -v ./...
