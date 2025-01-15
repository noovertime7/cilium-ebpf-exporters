# Compiler and flags
CLANG ?= clang
CFLAGS := -O2 -g -Wall -Werror

# eBPF specific flags
EBPF_CFLAGS := -target bpf \
	-D__TARGET_ARCH_x86 \
	-I/usr/include/x86_64-linux-gnu \
	-I. \
	-I./headers \
	-c

# Source and output directories
EXAMPLES_DIR := examples
SOURCES := $(wildcard $(EXAMPLES_DIR)/*.c)
OBJECTS := $(SOURCES:%.c=%.bpf.o)

# Default target
all: $(OBJECTS)

# Rule to build .bpf.o files from .c files
%.bpf.o: %.c
	$(CLANG) $(EBPF_CFLAGS) $(CFLAGS) -o $@ $<

# Clean target
clean:
	rm -f $(OBJECTS)

.PHONY: all clean
