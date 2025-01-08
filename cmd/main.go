//go:build linux
// +build linux

// This program demonstrates attaching an eBPF program to a kernel symbol.
// The eBPF program will be attached to the start of the sys_execve
// kernel function and prints out the number of times it has been called
// every second.
package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/noovertime7/cilium-ebpf-exporters/exporters"
)

func main() {
	// 创建 BPF 加载器
	loader := exporters.New()

	// 加载 eBPF 程序
	if err := loader.Load(); err != nil {
		log.Fatalf("Failed to load eBPF program: %v", err)
	}

	// 设置信号处理
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	// 等待中断信号
	<-stopper
	log.Println("Received signal, exiting..")
}
