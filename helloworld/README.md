
Mapの書き方変わった？
https://lore.kernel.org/all/d8928aad-851a-b9a4-a32b-8682b1be686@linux.intel.com/t/

```

apt install libbpf-dev clang-14

bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

