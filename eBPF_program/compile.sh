echo "------XDP PROG AND CHECK-------"
clang -O2 -g -Wall -target bpf -c xdp_prog.c -o xdp_prog.o
clang -O2 -g -Wall -target bpf -c xdp_check.c -o xdp_check.o
echo "------PROG LOADER------"
gcc prog_load.c -o loader -lbpf -lelf -lz
