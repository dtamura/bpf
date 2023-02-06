// +build ignore

#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>


char __license[] SEC("license") = "Dual MIT/GPL";

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u64));
    __uint(max_entries, 1);
} kprobe_map SEC(".maps");


struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u64);
	__type(value, struct sock *);
	__uint(max_entries, 1024);
} tcp_sendmsg_args SEC(".maps");

struct event {
	u16 sport;
	u16 dport;
	u32 saddr;
	u32 daddr;
	u32 srtt;
};
struct event *unused_event __attribute__((unused));



SEC("kprobe/sys_execve")
int kprobe_execve() {
	u32 key     = 0;
	u64 initval = 1, *valp;

	valp = bpf_map_lookup_elem(&kprobe_map, &key);
	if (!valp) {
		bpf_map_update_elem(&kprobe_map, &key, &initval, BPF_ANY);
		return 0;
	}
	__sync_fetch_and_add(valp, 1);

	return 0;
}

SEC("kprobe/tcp_sendmsg")
int kprobe__tcp_sendmsg(struct pt_regs *ctx) {
	u64 pid_tgid = bpf_get_current_pid_tgid();
	struct sock *parm1 = (struct sock *)PT_REGS_PARM1(ctx);
    struct sock *skp = parm1;
	bpf_map_update_elem(&tcp_sendmsg_args, &pid_tgid, &skp, BPF_ANY);
	return 0;
}
