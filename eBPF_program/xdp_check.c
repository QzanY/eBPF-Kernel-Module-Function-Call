#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int check(struct xdp_md *ctx) {

    char* fmt= "FONKSIYON ATESLENDI";
    bpf_trace_printk(fmt,20);
    return XDP_DROP;
}

char _license[] SEC("license") = "GPL";

