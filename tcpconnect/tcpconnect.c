// +build ignore

#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN 16
#endif

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
	__uint(max_entries, 1);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} pkt_counter SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(key_size, sizeof(struct sock *));
	__uint(value_size, sizeof(__u64));
	__uint(max_entries, 1024);
	// __uint(pinning, LIBBPF_PIN_BY_NAME);
} tcp_ongoing_connect_pid SEC(".maps");

SEC("kprobe/tcp_v4_connect")
int BPF_KPROBE(kprobe__tcp_v4_connect, struct sock *sk)
{
	pid_t pid;
    char comm[TASK_COMM_LEN];

	u64 pid_tgid = bpf_get_current_pid_tgid();
    bpf_map_update_elem(&tcp_ongoing_connect_pid, &sk, &pid_tgid, BPF_ANY);

    pid = pid_tgid >> 32;
    bpf_get_current_comm(&comm, sizeof(comm));
	bpf_printk("KPROBE ENTRY pid = %d, comm = %s\n", pid, comm);
	return 0;
}

SEC("kretprobe/tcp_v4_connect")
int BPF_KRETPROBE(kretprobe__tcp_v4_connect, struct sock *sk)
{
	u64 *pid_tgid_p = bpf_map_lookup_elem(&tcp_ongoing_connect_pid, &sk);
    if (!pid_tgid_p) {
        return 0;
    }

	return 0;
}
