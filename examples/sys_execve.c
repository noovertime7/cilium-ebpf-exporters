// go:build ignore

#include "common.h"
// Max number of disks we expect to see on the host
#define MAX_DISKS 255

// 27 buckets for latency, max range is 33.6s .. 67.1s
#define MAX_LATENCY_SLOT 27

char __license[] SEC("license") = "Dual MIT/GPL";

struct sys_execve_info
{
  char name[16];
};


struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, (MAX_LATENCY_SLOT + 1) * MAX_DISKS);
    __type(key, struct sys_execve_info);
    __type(value, u64);
} sys_execve_count SEC(".maps");


SEC("kprobe/__x64_sys_execve")
int kprobe_execve()
{
  u64 initval = 1, *valp;
  struct sys_execve_info info = {};

  // 获取进程名
  bpf_get_current_comm(&info.name, sizeof(info.name));


  valp = bpf_map_lookup_elem(&sys_execve_count, &info);
  if (!valp)
  {
    bpf_printk("First hit, initializing counter\n");
    bpf_map_update_elem(&sys_execve_count, &info, &initval, BPF_ANY);
    return 0;
  }
  
  __sync_fetch_and_add(valp, 1);
  bpf_printk("Counter incremented, current value: %lu\n", *valp);

  return 0;
}