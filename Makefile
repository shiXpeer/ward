VERSION ?= 0.4.8-dev
LDFLAGS = -s -w -X shixpeer.com/ward/internal/buildinfo.Version=$(VERSION)
.PHONY: build test check fmt clean
build:
	mkdir -p bin
	CGO_ENABLED=0 go build -trimpath -buildvcs=false -ldflags '$(LDFLAGS)' -o bin/shixpeer-ward-agent ./cmd/shixpeer-ward-agent
	CGO_ENABLED=0 go build -trimpath -buildvcs=false -ldflags '$(LDFLAGS)' -o bin/shixpeer-ward-beacon ./cmd/shixpeer-ward-beacon
	CGO_ENABLED=0 go build -trimpath -buildvcs=false -ldflags '$(LDFLAGS)' -o bin/shixpeer-ward-relay ./cmd/shixpeer-ward-relay

test:
	go test -race ./...

check:
	test -z "$$(gofmt -l cmd internal pkg)"
	go vet ./...
	go test -race ./...

fmt:
	gofmt -w cmd internal pkg

clean:
	rm -rf bin dist

.PHONY: ubuntu-bundle
ubuntu-bundle:
	mkdir -p dist/ubuntu/bin dist/ubuntu/configs dist/ubuntu/packaging dist/ubuntu/docs
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -buildvcs=false -ldflags '$(LDFLAGS)' -o dist/ubuntu/bin/shixpeer-ward-agent-linux-amd64 ./cmd/shixpeer-ward-agent
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -buildvcs=false -ldflags '$(LDFLAGS)' -o dist/ubuntu/bin/shixpeer-ward-agent-linux-arm64 ./cmd/shixpeer-ward-agent
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -buildvcs=false -ldflags '$(LDFLAGS)' -o dist/ubuntu/bin/shixpeer-ward-beacon-linux-amd64 ./cmd/shixpeer-ward-beacon
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -buildvcs=false -ldflags '$(LDFLAGS)' -o dist/ubuntu/bin/shixpeer-ward-beacon-linux-arm64 ./cmd/shixpeer-ward-beacon
	cp configs/beacon.default.json dist/ubuntu/configs/
	cp packaging/shixpeer-ward-install-beacon.sh dist/ubuntu/packaging/
	cp docs/ubuntu-deployment.md docs/ubuntu-deployment.uk.md docs/ubuntu-update.md docs/ubuntu-update.uk.md dist/ubuntu/docs/
	cp LICENSE NOTICE THIRD_PARTY_NOTICES.md dist/ubuntu/
	install -m 0644 "$$(go env GOROOT)/LICENSE" dist/ubuntu/GO_LICENSE
	COPYFILE_DISABLE=1 tar --no-xattrs $(if $(filter Darwin,$(shell uname -s)),--no-mac-metadata) -czf dist/shixpeer-ward-ubuntu.tar.gz -C dist ubuntu

# Explicit Docker integration test; local fixture feed only, never live CVE feeds.
.PHONY: test-ubuntu
test-ubuntu: ubuntu-bundle
	docker run --rm --mount type=bind,source="$(CURDIR)/dist/ubuntu",target=/bundle,readonly --mount type=bind,source="$(CURDIR)/packaging/tests/ubuntu-container.sh",target=/ward-test.sh,readonly ubuntu:24.04 bash /ward-test.sh
