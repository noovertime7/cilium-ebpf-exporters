CLANG ?= clang
CFLAGS ?= -O2 -g -Wall -Werror


EBPF_ROOT = /home/ebpf/code/clium-ebpf-exporters
MY_HEADERS = $(EBPF_ROOT)/headers

build: generate
	go build -o bin/biolatency cmd/main.go


generate: export BPF_CLANG := $(CLANG)
generate: export BPF_CFLAGS := $(CFLAGS)
generate: export BPF_HEADERS=$(MY_HEADERS)
generate:
	go generate ./...
