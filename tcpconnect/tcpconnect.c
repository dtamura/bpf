// +build ignore

#include "vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN 16
#endif

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct
{
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
	__uint(max_entries, 1);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} pkt_counter SEC(".maps");

struct
{
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u64);
	__type(value, struct sock *);
	__uint(max_entries, 1024);
	// __uint(pinning, LIBBPF_PIN_BY_NAME);
} tcp_ongoing_connect_pid SEC(".maps");

// ref: https://github.com/DataDog/datadog-agent/blob/main/pkg/network/ebpf/c/tracer.h
typedef enum
{
	// Connection type
	CONN_TYPE_UDP = 0,
	CONN_TYPE_TCP = 1,

	// Connection family
	CONN_V4 = 0 << 1,
	CONN_V6 = 1 << 1,
} metadata_mask_t;

// Connection Info
typedef struct
{
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

void init_conn_tuple_t(conn_tuple_t *t)
{
	t->saddr_h = 0;
	t->saddr_l = 0;
	t->daddr_h = 0;
	t->daddr_l = 0;
	t->dport = 0;
	t->sport = 0;
	t->netns = 0;
	t->metadata = 0;
}

// Connection Stats
typedef struct
{
	__u64 sent_bytes;
	__u64 recv_bytes;
	__u64 timestamp;
	__u64 sent_packets;
	__u64 recv_packets;
	__u8 direction;
} conn_stats_ts_t;

void init_conn_stats_ts_t(conn_stats_ts_t *t)
{
	t->sent_bytes = 0;
	t->recv_bytes = 0;
	t->timestamp = 0;
	t->sent_packets = 0;
	t->recv_packets = 0;
	t->direction = 0;
}
struct
{
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, conn_tuple_t);
	__type(value, conn_stats_ts_t);
	__uint(max_entries, 1024);
} conn_stats SEC(".maps");

// TCP Stats
typedef struct
{
	__u32 retransmits;
	__u32 rtt;
	__u32 rtt_var;

	// Bit mask containing all TCP state transitions tracked by our tracer
	__u16 state_transitions;
} tcp_stats_t;
void init_tcp_stats(tcp_stats_t *t)
{
	t->retransmits = 0;
	t->rtt = 0;
	t->rtt_var = 0;
	t->state_transitions = 0;
}
struct
{
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, conn_tuple_t);
	__type(value, tcp_stats_t);
	__uint(max_entries, 1024);
} tcp_stats SEC(".maps");

// TCP接続に関する全情報
typedef struct
{
	conn_tuple_t tup;
	conn_stats_ts_t conn_stats;
	tcp_stats_t tcp_stats;
} conn_t;

// struct sockからコネクション情報を読み出す
// 成功で1, 失敗は0を返却
static __always_inline int read_conn_tuple(conn_tuple_t *t, struct sock *skp, u64 pid_tgid)
{
	// pid
	t->pid = pid_tgid >> 32;

	// netns
	struct net *ct_net = NULL;
	BPF_CORE_READ_INTO(&ct_net, skp, __sk_common.skc_net);
	u32 net_ns_inum = 0;
	BPF_CORE_READ_INTO(&net_ns_inum, ct_net, ns.inum);
	t->netns = net_ns_inum;

	// src / dst addr
	BPF_CORE_READ_INTO((u32 *)(&t->saddr_l), skp, __sk_common.skc_rcv_saddr);
	BPF_CORE_READ_INTO((u32 *)(&t->daddr_l), skp, __sk_common.skc_daddr);

	if (t->saddr_l == 0 || t->daddr_l == 0)
	{
		bpf_printk("ERR(read_conn_tuple.v4): src or dst addr not set src=%d, dst=%d\n", t->saddr_l, t->daddr_l);
		return 0;
	}

	// port
	__u16 dport = 0;
	BPF_CORE_READ_INTO(&dport, skp, __sk_common.skc_dport);
	t->dport = bpf_ntohs(dport); // バイトオーダー
	BPF_CORE_READ_INTO(&t->sport, skp, __sk_common.skc_num);
	if (t->sport == 0 || t->dport == 0)
	{
		bpf_printk("ERR: sport or dport  not set sport=%d, dport=%d\n", t->sport, t->dport);
		return 0;
	}

	return 1;
}

// TCPの統計値を更新する
static __always_inline void update_tcp_stats(conn_tuple_t *key, tcp_stats_t stats)
{
	// TODO: Datadog Agentはここで tcp_statsのキーからpid情報を捨てている（0にしている）

	// initialize-if-no-exist the connection state, and load it
	tcp_stats_t empty = {};
	bpf_map_update_elem(&tcp_stats, key, &empty, BPF_NOEXIST); // Mapに未登録であれば空で挿入

	tcp_stats_t *val = bpf_map_lookup_elem(&tcp_stats, key);
	if (val == NULL)
	{
		return;
	}

	if (stats.retransmits > 0)
	{
		__sync_fetch_and_add(&val->retransmits, stats.retransmits);
	}

	if (stats.rtt > 0)
	{
		// For more information on the bit shift operations see:
		// https://elixir.bootlin.com/linux/v4.6/source/net/ipv4/tcp.c#L2686
		val->rtt = stats.rtt >> 3;
		val->rtt_var = stats.rtt_var >> 2;
	}

	if (stats.state_transitions > 0)
	{
		val->state_transitions |= stats.state_transitions;
	}
}

static __always_inline void handle_tcp_stats(conn_tuple_t *key, struct sock *skp, u8 state)
{
	// 情報取得
	u32 rtt = 0, rtt_var = 0;
	BPF_CORE_READ_INTO(&rtt, (struct tcp_sock *)(skp), srtt_us);
	BPF_CORE_READ_INTO(&rtt_var, (struct tcp_sock *)(skp), mdev_us);

	tcp_stats_t stats = {.retransmits = 0, .rtt = rtt, .rtt_var = rtt_var};

	update_tcp_stats(key, stats);
}

// コネクションの統計値を更新する
static __always_inline void update_conn_stats(conn_tuple_t *key, size_t sent_bytes, size_t recv_bytes, u64 ts, struct sock *skp)
{
	conn_stats_ts_t empty = {};
	init_conn_stats_ts_t(&empty);
	bpf_map_update_elem(&conn_stats, key, &empty, BPF_NOEXIST); // Mapに未登録であれば空で挿入

	conn_stats_ts_t *val = bpf_map_lookup_elem(&conn_stats, key);
	if (!val)
	{
		return;
	}
	val->timestamp = ts;
	// u64 sent_bytes = 0;
	// if (sent_bytes) {
	// 	__sync_fetch_and_add(&val->sent_bytes, sent_bytes);
	// }
	// u64 recv_bytes = 0;
	// if (recv_bytes) {
	// 	__sync_fetch_and_add(&val->recv_bytes, recv_bytes);
	// }
}

static __always_inline int handle_message(conn_tuple_t *t, size_t sent_bytes, size_t recv_bytes, struct sock *skp)
{
	u64 ts = bpf_ktime_get_ns();
	update_conn_stats(t, sent_bytes, recv_bytes, ts, skp);
	return 0;
}

static __always_inline void cleanup_conn(conn_tuple_t *t, struct sock *sk)
{
	conn_t conn = {.tup = *t};
	conn_stats_ts_t *cst = NULL;

	// tcp_stats からクリア
	tcp_stats_t *tst = bpf_map_lookup_elem(&tcp_stats, &(conn.tup));
	if (tst)
	{
		conn.tcp_stats = *tst;
		bpf_map_delete_elem(&tcp_stats, &(conn.tup));
	}

	conn.tcp_stats.state_transitions |= (1 << TCP_CLOSE);

	// conn_statsからクリア
	cst = bpf_map_lookup_elem(&conn_stats, &(conn.tup));
	if (cst)
	{
		conn.conn_stats = *cst;
		bpf_map_delete_elem(&conn_stats, &(conn.tup));
	}
}

SEC("kprobe/tcp_v4_connect")
int BPF_KPROBE(kprobe__tcp_v4_connect, struct sock *skp)
{
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
int BPF_KRETPROBE(kretprobe__tcp_v4_connect, long ret)
{
	// TCP v4 接続が終わった
	u64 pid_tgid = bpf_get_current_pid_tgid();
	pid_t pid = pid_tgid >> 32;
	bpf_printk("kretprobe/tcp_v4_connect status = %ld, pid = %u\n", ret, pid);

	if (ret != 0)
	{ // TCP 接続失敗
		bpf_printk("connect fail: exit code = %ld", ret);
		bpf_map_delete_elem(&tcp_ongoing_connect_pid, &pid_tgid);
	}

	// Socketへのポインタをルックアップ
	struct sock **skpp = bpf_map_lookup_elem(&tcp_ongoing_connect_pid, &pid_tgid);
	if (!skpp)
	{
		bpf_printk("no entry");
		return 0;
	}
	struct sock *skp = *skpp;

	// bpf_map_delete_elem(&tcp_ongoing_connect_pid, &pid_tgid);

	// 情報収集
	conn_tuple_t key = {};
	init_conn_tuple_t(&key);
	if (!read_conn_tuple(&key, skp, pid_tgid))
	{
		return 0;
	}

	handle_tcp_stats(&key, skp, 0);
	handle_message(&key, 0, 0, skp);

	return 0;
}

SEC("kprobe/tcp_finish_connect")
int BPF_KPROBE(kprobe__tcp_finish_connect, struct sock *sk, struct sk_buff *skb)
{
	struct sock *skp = sk;

	// pid_tgid へのポインタをルックアップ
	u64 *pid_tgid_p = bpf_map_lookup_elem(&tcp_ongoing_connect_pid, &skp);
	if (!pid_tgid_p)
	{
		return 0;
	}
	u64 pid_tgid = *pid_tgid_p;
	bpf_map_delete_elem(&tcp_ongoing_connect_pid, &skp);
	bpf_printk("kprobe/tcp_finish_connect: tgid: %u, pid: %u\n", pid_tgid >> 32, pid_tgid & 0xFFFFFFFF);

	conn_tuple_t key = {};
	init_conn_tuple_t(&key);
	if (!read_conn_tuple(&key, skp, pid_tgid))
	{
		return 0;
	}
	handle_tcp_stats(&key, skp, 0);
	handle_message(&key, 0, 0, skp);

	return 0;
}

SEC("kprobe/tcp_close")
int BPF_KPROBE(kprobe__tcp_close, struct sock *sk, long timeout)
{
	struct sock *skp = sk;
	conn_tuple_t key = {};
	init_conn_tuple_t(&key);
	u64 pid_tgid = bpf_get_current_pid_tgid();

	if (!bpf_map_delete_elem(&tcp_ongoing_connect_pid, &skp))
	{ // 確立せずに終了した接続
		bpf_printk("tcp_close called never estabilished: pid=%u", pid_tgid << 32);
	}

	// clear_sockfd_maps(sk);

	if (!read_conn_tuple(&key, skp, pid_tgid))
	{
		return 0;
	}
	bpf_printk("kprobe/tcp_close: pid: %u, netns: %u, sport: %u, dport: %u\n", pid_tgid >> 32, key.netns, key.sport, key.dport);

	cleanup_conn(&key, skp);

	return 0;
}