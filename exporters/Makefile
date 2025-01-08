CLANG ?= clang
CFLAGS ?= -O2 -g -Wall -Werror


EBPF_ROOT = /home/ebpf/code/clium-ebpf-demo
MY_HEADERS = $(EBPF_ROOT)/headers

build: generate
	cd cmd/ringbuffer && \
	go build -o ../../bin/ringbuffer .

generate: export BPF_CLANG := $(CLANG)
generate: export BPF_CFLAGS := $(CFLAGS)
generate: export BPF_HEADERS=$(MY_HEADERS)
generate:
	go generate ./...
