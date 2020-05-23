all: subspace-linux-amd64

BUILD_VERSION?=unknown

subspace-linux-amd64:
	go get -u github.com/kevinburke/go-bindata/...\
	&& go mod download \
	&& go run github.com/kevinburke/go-bindata/go-bindata --pkg main static/... templates/... email/.. \
	&& go generate \
	&& go fmt \
	&& go vet --all
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
	go build -v --compiler gc --ldflags "-extldflags -static -s -w -X main.version=${BUILD_VERSION}" -o subspace-linux-amd64

clean:
	rm -f subspace-linux-amd64 bindata.go

.PHONY: clean
