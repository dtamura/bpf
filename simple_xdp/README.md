```
clang -g -O2 -target bpf \
   -D__TARGET_ARCH_x86 \
   -c count.c -o count.o



   -D__TARGET_ARCH_$(uname -m | sed 's/x86_64/x86/') \


bpftool prog load count.o /sys/fs/bpf/demo type xdp
bpftool net attach xdpgeneric id 42 dev ens33
bpftool net detach xdpgeneric dev ens33

bpftool prog dump xlated id 42 linum

rm /sys/fs/bpf/demo

セクションヘッダ情報表示
readelf -S

ELFファイルヘッダ
readelf -h

プログラムヘッダ
readelf -l

# -h -l -S 
readelf -e

改行なし
readelf -W



HEX表示
readelf -x <section num> 

文字列表示
readelf -p <section num>


https://udzura.hatenablog.jp/entry/2021/07/01/235448

# --all-headers
llvm-objdump -x count.o


# 16進数とASCII表示
hexdump -C count.o


Disassembly
llvm-objdump -d count.o


bpftool prog load count.o /sys/fs/bpf/demo type xdp