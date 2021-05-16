.DEFAULT_GOAL := help
.PHONY: help

BUILD_VERSION?=unknown


help:  ## Display this help message and exit
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

build: clean ## Build the binary
	@echo "Creating bindata.go..."
	@go get -u github.com/kevinburke/go-bindata/go-bindata
	@go run github.com/kevinburke/go-bindata/go-bindata -o cmd/subspace/bindata.go --prefix "web/" --pkg main web/...
	@echo "+++ bindata.go created"

	@echo "Compiling subspace..."
	@CGO_ENABLED=0 \
		go build -v --compiler gc --ldflags "-extldflags -static -s -w -X main.version=${BUILD_VERSION}" -o subspace ./cmd/subspace \
			&& rm cmd/subspace/bindata.go
	@echo "+++ subspace compiled"

clean:  ## Remove old binaries
	rm -f subspace cmd/subspace/bindata.go
