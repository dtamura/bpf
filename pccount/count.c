// +build ignore

#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>


char __license[] SEC("license") = "Dual MIT/GPL";

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u64));
} packet_counter SEC(".maps");

int counter(struct __sk_buff *ctx) {
    __u32 index = 0;
	__u64 *valp = bpf_map_lookup_elem(&packet_counter, &index);
    if (valp)
        *valp += 1;
    return TC_ACT_OK;
}