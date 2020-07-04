all: subspace

BUILD_VERSION?=unknown

subspace:
	go run github.com/kevinburke/go-bindata/go-bindata -o cmd/subspace/bindata.go --prefix "web/" --pkg main web/... \
		&& CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
		go build -v --compiler gc --ldflags "-extldflags -static -s -w -X main.version=${BUILD_VERSION}" -o subspace ./cmd/subspace

clean:
	rm -f subspace cmd/subspace/bindata.go

.PHONY: clean
