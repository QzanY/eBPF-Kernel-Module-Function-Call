#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/if_ether.h>
#include <arpa/inet.h>

#define ETH_P_IP 0x0800

struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 3);  // Just one entry for this example
    __type(key, __u32);
    __type(value, __u32);
} program_array SEC(".maps");

extern int put_num_haha(void) __ksym;

SEC("xdp")
int xdp_prog(struct xdp_md *ctx) {
    // Parse Ethernet header
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;

    if ((void *)(eth + 1) > data_end)
        return XDP_DROP;

    if (eth->h_proto != htons(ETH_P_IP))
        return XDP_DROP;


    struct iphdr *ip = data + sizeof(*eth);
    if ((void *)(ip + 1) > data_end)
        return XDP_DROP;

    if (ip->protocol == IPPROTO_TCP) {
        if ((void *)(ip + 1) > data_end)
            return XDP_DROP;
        struct tcphdr *tcp = (void *)ip + sizeof(*ip);
        if ((void *)(tcp + 1) > data_end)
            return XDP_DROP;
        char fmt[] = "TCP Packet received  %u\n";
        bpf_trace_printk(fmt,sizeof(fmt)+sizeof(tcp->dest),tcp->dest);
    
        if (tcp->dest == 8080)
        {
            char fmt[] = "TCP Packet dropped on port 8080  %d\n";
            bpf_trace_printk(fmt,sizeof(fmt),tcp->dest);
            return XDP_DROP;
        }
    
    }
    if (ip->protocol == IPPROTO_ICMP)
	{
    	    __u32 key = 0;
	    bpf_tail_call(ctx,&program_array,key);
	}

    int a = put_num_haha();
    char fmt[] = "Printing the num: %d\n";
    bpf_trace_printk(fmt,sizeof(fmt),a);

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";

