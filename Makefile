VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -X main.version=$(VERSION)

.PHONY: build generate test vet lint simulate clean install

build:
	go build -ldflags "$(LDFLAGS)" -o bin/wraith ./cmd/wraith

# Regenerates internal/sensor/wraith_*_bpfel.{go,o} from bpf/wraith.bpf.c.
# Only needed after touching the C source — the generated files are checked
# in, so a plain `make build` never needs clang.
generate:
	BPF2GO_CC=clang BPF2GO_STRIP=$(shell command -v llvm-strip || echo llvm-strip) \
		go generate ./...

test:
	go test ./...

vet:
	go vet ./...

lint: vet
	@command -v golangci-lint >/dev/null && golangci-lint run || \
		echo "golangci-lint not installed, ran go vet only"

simulate:
	$(MAKE) -C scripts/simulate all

clean:
	rm -rf bin
	$(MAKE) -C scripts/simulate clean

install: build
	install -Dm755 bin/wraith /usr/local/bin/wraith
