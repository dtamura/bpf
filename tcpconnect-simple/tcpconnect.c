// +build ignore

#include "vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN 16
#endif

// inlude/linux/socket.h
#define AF_INET 2   /* Internet IP Protocol 	*/
#define AF_INET6 10 /* IP version 6			*/

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u64);
	__type(value, struct sock *);
	__uint(max_entries, 1024);
} tcp_ongoing_connect_pid SEC(".maps");

// ref: https://github.com/DataDog/datadog-agent/blob/main/pkg/network/ebpf/c/tracer.h
typedef enum {
	// Connection type
	CONN_TYPE_UDP = 0,
	CONN_TYPE_TCP = 1,

	// Connection family
	CONN_V4 = 0 << 1,
	CONN_V6 = 1 << 1,
} metadata_mask_t;

// Connection Info
typedef struct {
	__u64 saddr_h; // for IPv6
	__u64 saddr_l;
	__u64 daddr_h; // for IPv6
	__u64 daddr_l;
	__u16 sport;
	__u16 dport;
	__u32 pid;
	__u8 comm[TASK_COMM_LEN]; // 追加
} conn_tuple_t;

void init_conn_tuple_t(conn_tuple_t *t) {
	t->saddr_h = 0;
	t->saddr_l = 0;
	t->daddr_h = 0;
	t->daddr_l = 0;
	t->dport   = 0;
	t->sport   = 0;
}

struct event {
	conn_tuple_t tup;
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} events SEC(".maps");

// Force emitting struct event into the ELF.
const struct event *unused __attribute__((unused));

// struct sockからコネクション情報を読み出す
// 成功で1, 失敗は0を返却
static __always_inline int read_conn_tuple(conn_tuple_t *t, struct sock *skp, u64 pid_tgid) {
	// pid
	t->pid = pid_tgid >> 32;

	// comm
	bpf_get_current_comm(&t->comm, sizeof(t->comm));

	// family
	unsigned short family = 0;
	BPF_PROBE_READ_INTO(&family, skp, __sk_common.skc_family);

	// addr
	if (family == AF_INET) { // IPv4
		BPF_CORE_READ_INTO((u32 *)(&t->saddr_l), skp, __sk_common.skc_rcv_saddr);
		BPF_CORE_READ_INTO((u32 *)(&t->daddr_l), skp, __sk_common.skc_daddr);

		if (t->saddr_l == 0 || t->daddr_l == 0) {
			bpf_printk("ERR(read_conn_tuple.v4): src or dst addr not set src=%d, dst=%d\n", t->saddr_l, t->daddr_l);
			return 0;
		}

	} else {
		// bpf_printk("ERR: not ipv4 family: __skc_family=%u", family);
		return 0;
	}

	// IPフィルタリング
	// if (t->daddr_l != 2647656349) { // 157.7.208.157 (inet-ip.info)
	// 	return 0;
	// }

	// port
	__u16 dport = 0;
	BPF_CORE_READ_INTO(&dport, skp, __sk_common.skc_dport);
	t->dport = bpf_ntohs(dport); // バイトオーダー
	BPF_CORE_READ_INTO(&t->sport, skp, __sk_common.skc_num);
	if (t->sport == 0 || t->dport == 0) {
		bpf_printk("ERR: sport or dport  not set sport=%d, dport=%d\n", t->sport, t->dport);
		return 0;
	}

	return 1;
}

/*****************************************/

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

	bpf_printk("kprobe/tcp_v4_connect pid = %d, comm = %s\n", pid, comm);
	return 0;
}

SEC("kretprobe/tcp_v4_connect")
int BPF_KRETPROBE(kretprobe__tcp_v4_connect, long ret) {
	// TCP v4 接続が終わった
	u64 pid_tgid = bpf_get_current_pid_tgid();
	pid_t pid    = pid_tgid >> 32;
	bpf_printk("kretprobe/tcp_v4_connect status = %ld, pid = %u\n", ret, pid);

	if (ret != 0) { // TCP 接続失敗
		bpf_printk("connect fail: exit code = %ld", ret);
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
	if (!read_conn_tuple(&key, skp, pid_tgid)) {
		return 0;
	}

	// Ring Bufferへ送信
	struct event *conn_info;
	conn_info = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
	if (!conn_info) {
		return 0;
	}
	conn_info->tup = key;
	bpf_ringbuf_submit(conn_info, 0);

	return 0;
}

/*****************************************/
