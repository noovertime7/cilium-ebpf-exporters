

# Cilium eBPF Exporters

[English](#english) | [中文](#中文)

## English

Introduction
Cilium eBPF Exporters is a monitoring tool that leverages eBPF technology to collect and export system metrics to Prometheus. It provides a flexible way to monitor system performance and behavior at the kernel level with minimal overhead.

Features
- Supports various eBPF program types (kprobe, tracepoint)
- Prometheus metrics export
- YAML-based configuration
- BTF support for CO-RE (Compile Once – Run Everywhere)
- Debug support with bpf_printk

Quick Start
1. Build the eBPF programs:
   make

2. Run the exporter:
   ./bin/cilium-ebpf-exporters -config examples/sys_execve.yaml

3. View metrics:
   curl http://localhost:9435/metrics

Configuration
Configuration is done through YAML files. Example:

program_type: kprobe
metrics:
  histograms:
    - name: sys_execve_count
      help: sys_execve_count histogram
kaddrs:
  - "__x64_sys_execve"

System Requirements
- Linux kernel 4.18+
- Clang/LLVM 10+
- Go 1.17+

License
MIT License

---

## 中文

简介
Cilium eBPF Exporters 是一个基于 eBPF 技术的监控工具，用于收集系统指标并导出到 Prometheus。它提供了一种以最小开销监控系统性能和行为的灵活方式。

特性
- 支持多种 eBPF 程序类型（kprobe、tracepoint）
- Prometheus 指标导出
- 基于 YAML 的配置
- 支持 BTF 实现 CO-RE（一次编译，到处运行）
- 支持使用 bpf_printk 进行调试

快速开始
1. 编译 eBPF 程序：
   make

2. 运行导出器：
   ./bin/cilium-ebpf-exporters -config examples/sys_execve.yaml

3. 查看指标：
   curl http://localhost:9435/metrics

配置说明
通过 YAML 文件进行配置。示例：

program_type: kprobe
metrics:
  histograms:
    - name: sys_execve_count
      help: sys_execve_count histogram
kaddrs:
  - "__x64_sys_execve"

调试
可以通过以下命令查看 eBPF 程序的调试输出：
sudo cat /sys/kernel/debug/tracing/trace_pipe

系统要求
- Linux 内核 4.18+
- Clang/LLVM 10+
- Go 1.17+

许可证
MIT License
