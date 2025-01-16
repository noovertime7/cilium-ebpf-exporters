// go:build ignore

#include "common.h"

char __license[] SEC("license") = "Dual MIT/GPL";

struct bpf_map_def SEC("maps") sys_execve_count = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(u32),
    .value_size = sizeof(u64),
    .max_entries = 1,
};

SEC("kprobe/__x64_sys_execve")
int kprobe_execve()
{
  u32 key = 0;
  u64 initval = 1, *valp;

  bpf_printk("Entering kprobe_execve\n");

  valp = bpf_map_lookup_elem(&sys_execve_count, &key);
  if (!valp)
  {
    bpf_printk("First hit, initializing counter\n");
    bpf_map_update_elem(&sys_execve_count, &key, &initval, BPF_ANY);
    return 0;
  }
  
  __sync_fetch_and_add(valp, 1);
  bpf_printk("Counter incremented, current value: %lu\n", *valp);

  return 0;
}