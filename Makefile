VERSION ?= $(shell git describe --tags --always --dirty)
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: build test vet clean release deb

build:
	go build -ldflags="$(LDFLAGS)" -o mattlab .

test:
	go test -race -v ./...

vet:
	go vet ./...

clean:
	rm -f mattlab mattlab-*

release:
	@for os in linux darwin windows; do \
		for arch in amd64 arm64; do \
			echo "Building $$os/$$arch..."; \
			CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch \
			go build -ldflags="$(LDFLAGS)" -o mattlab-$$os-$$arch .; \
		done; \
	done

deb:
	@mkdir -p build/deb/opt/mattlab
	@mkdir -p build/deb/opt/mattlab/domains
	@mkdir -p build/deb/etc/systemd/system
	@mkdir -p build/deb/DEBIAN
	cp mattlab build/deb/opt/mattlab/
	cp domains/*.txt build/deb/opt/mattlab/domains/
	envsubst < packaging/deb/control.tmpl > build/deb/DEBIAN/control
	cp packaging/deb/mattlab.service build/deb/etc/systemd/system/
	dpkg-deb --build build/deb mattlab_$(VERSION)_$(ARCH).deb
