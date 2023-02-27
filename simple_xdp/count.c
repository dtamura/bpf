// +build ignore

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

char __license[] SEC("license") = "Dual MIT/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
	__uint(max_entries, 1);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} pkt_counter SEC(".maps");

SEC("xdp")
int xdp_program(struct xdp_md *ctx) {
	__u32 *count, index = 0;
	count = bpf_map_lookup_elem(&pkt_counter, &index);
	if (count == NULL) {
		return XDP_DROP;
	}
	__sync_fetch_and_add(count, 1);
	return XDP_PASS;
}