// +build ignore

#include "vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

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
	__type(key, __u64);
	__type(value, struct sock *);
	__uint(max_entries, 1024);
	// __uint(pinning, LIBBPF_PIN_BY_NAME);
} tcp_ongoing_connect_pid SEC(".maps");

// ref: https://github.com/DataDog/datadog-agent/blob/main/pkg/network/ebpf/c/tracer.h
typedef struct {
	__u64 saddr_h; // for IPv6
	__u64 saddr_l;
	__u64 daddr_h; // for IPv6
	__u64 daddr_l;
	__u16 sport;
	__u16 dport;
	__u32 netns;
	__u32 pid;
	// Metadata description:
	// First bit indicates if the connection is TCP (1) or UDP (0)
	// Second bit indicates if the connection is V6 (1) or V4 (0)
	__u32 metadata; // This is that big because it seems that we atleast need a 32-bit aligned struct
} conn_tuple_t;

void init_conn_tuple_t(conn_tuple_t *t) {
	t->saddr_h  = 0;
	t->saddr_l  = 0;
	t->daddr_h  = 0;
	t->daddr_l  = 0;
	t->dport    = 0;
	t->sport    = 0;
	t->netns    = 0;
	t->metadata = 0;
}

typedef struct {
	__u64 sent_bytes;
	__u64 recv_bytes;
	__u64 timestamp;
	__u64 sent_packets;
	__u64 recv_packets;
	__u8 direction;
} conn_stats_ts_t;

void init_conn_stats_ts_t(conn_stats_ts_t *t) {
	t->sent_bytes   = 0;
	t->recv_bytes   = 0;
	t->timestamp    = 0;
	t->sent_packets = 0;
	t->recv_packets = 0;
	t->direction    = 0;
}
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, conn_tuple_t);
	__type(value, conn_stats_ts_t);
	__uint(max_entries, 1024);
	// __uint(pinning, LIBBPF_PIN_BY_NAME);
} conn_stats SEC(".maps");

SEC("kprobe/tcp_v4_connect")
int BPF_KPROBE(kprobe__tcp_v4_connect, struct sock *skp) {
	// TCP v4で接続しようとしている
	pid_t pid;
	char comm[TASK_COMM_LEN];

	u64 pid_tgid = bpf_get_current_pid_tgid();
	// PID_TGID をキーにしてSocketへのポインタを格納
	bpf_map_update_elem(&tcp_ongoing_connect_pid, &pid_tgid, &skp, BPF_ANY);

	pid = pid_tgid >> 32;
	bpf_get_current_comm(&comm, sizeof(comm));

	bpf_printk("KPROBE ENTRY pid = %d, comm = %s\n", pid, comm);
	return 0;
}

SEC("kretprobe/tcp_v4_connect")
int BPF_KRETPROBE(kretprobe__tcp_v4_connect, long ret) {
	// TCP v4 接続が終わった
	u64 pid_tgid = bpf_get_current_pid_tgid();
	pid_t pid    = pid_tgid >> 32;
	bpf_printk("KPROBE EXIT status = %d, pid = %d\n", ret, pid);

	if (ret != 0) { // TCP 接続失敗
		bpf_printk("connect fail: exit code = %d", ret);
		bpf_map_delete_elem(&tcp_ongoing_connect_pid, &pid_tgid);
	}

	// Socketへのポインタをルックアップ
	struct sock **skpp = bpf_map_lookup_elem(&tcp_ongoing_connect_pid, &pid_tgid);
	if (!skpp) {
		bpf_printk("no entry");
		return 0;
	}
	struct sock *skp = *skpp;

	bpf_map_delete_elem(&tcp_ongoing_connect_pid, &pid_tgid);

	// 情報収集
	conn_tuple_t key = {};
	init_conn_tuple_t(&key);
	// src / dst addr
	BPF_CORE_READ_INTO((u32 *)(&key.saddr_l), skp, __sk_common.skc_rcv_saddr);
	BPF_CORE_READ_INTO((u32 *)(&key.daddr_l), skp, __sk_common.skc_daddr);

	bpf_printk("src=%d, dst=%d\n", key.saddr_l, key.daddr_l);
	if (key.saddr_l == 0 || key.daddr_l == 0) {
		bpf_printk("ERR(read_conn_tuple.v4): src or dst addr not set src=%d, dst=%d\n", key.saddr_l, key.daddr_l);
	}
	// port
	BPF_CORE_READ_INTO(&key.dport, skp, __sk_common.skc_dport);
	BPF_CORE_READ_INTO(&key.sport, skp, __sk_common.skc_num);
	bpf_printk("sport=%d, dport=%d\n", key.sport, key.dport);
	if (key.sport == 0 || key.dport == 0) {
		bpf_printk("ERR: sport or dport  not set sport=%d, dport=%d\n", key.sport, key.dport);
	}

	// コネクションの統計値の初期化
	conn_stats_ts_t empty = {};
	init_conn_stats_ts_t(&empty);

	bpf_map_update_elem(&conn_stats, &key, &empty, BPF_NOEXIST);
	conn_stats_ts_t *val = bpf_map_lookup_elem(&conn_stats, &key);
	if(!val) {
		return 0;
	}
	u64 ts = bpf_ktime_get_ns();
	val->timestamp = ts;
	u64 sent_bytes = 0;
	if (sent_bytes) {
        __sync_fetch_and_add(&val->sent_bytes, sent_bytes);
    }
	u64 recv_bytes = 0;
	if (recv_bytes) {
        __sync_fetch_and_add(&val->recv_bytes, recv_bytes);
    }

	return 0;
}
