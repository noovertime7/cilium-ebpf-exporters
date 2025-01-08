package exporters

import (
	"fmt"
	"log"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

// bpfObjects 包含所有 eBPF maps 和程序
//
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -cc clang bpf ./bpf/biolatency.bpf.c -- -I../headers
const mapKey uint32 = 0

type BPFLoader struct {
}

// New 创建一个新的 BPF 加载器实例
func New() *BPFLoader {
	return &BPFLoader{}
}

// Load 加载 eBPF 程序
func (l *BPFLoader) Load() error {
	// Name of the kernel function to trace.
	fn := "sys_execve"

	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	// 加载预编译的程序
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		return fmt.Errorf("loading objects: %v", err)
	}
	defer objs.Close()
	// Open a Kprobe at the entry point of the kernel function and attach the
	// pre-compiled program. Each time the kernel function enters, the program
	// will increment the execution counter by 1. The read loop below polls this
	// map value once per second.
	kp, err := link.Kprobe(fn, objs.KprobeExecve, nil)
	if err != nil {
		log.Fatalf("opening kprobe: %s", err)
	}
	defer kp.Close()

	// Read loop reporting the total amount of times the kernel
	// function was entered, once per second.
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	log.Println("Waiting for events..")

	for range ticker.C {
		var value uint64
		if err := objs.KprobeMap.Lookup(mapKey, &value); err != nil {
			log.Fatalf("reading map: %v", err)
		}
		log.Printf("%s called %d times\n", fn, value)
	}

	fmt.Println("eBPF program loaded and attached successfully.")
	return nil

}
