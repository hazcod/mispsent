
all: run

build:
	$$GOPATH/bin/goreleaser build --snapshot --config=.github/goreleaser.yml --rm-dist

run:
	go run ./cmd/... -config=dev.yml

clean:
	rm -r dist/ || true

test:
	go test -v ./...
