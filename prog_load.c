#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <net/if.h>
#include <unistd.h>
#include <signal.h>
#include <linux/bpf.h>
#include <linux/if_link.h>
#include <linux/version.h>

#define PROG_ARRAY_MAP_NAME "program_array"

// #define DEBUG

static int ifindex, prog_fd_prog, prog_fd_check, map_fd, ret ,dev_fd;

int load_bpf_object_file(const char *filename, struct bpf_object **obj) {
    //Here we open the object file and set the obj pointer. This function returns the pointer to the object file
    *obj = bpf_object__open_file(filename, NULL);
    if (!*obj) {
        fprintf(stderr, "Failed to open BPF object file: %s\n", filename);
        return -1;
    }

    //Here we load the object file to the kernel
    if (bpf_object__load(*obj)) {
        fprintf(stderr, "Failed to load BPF object file: %s\n", filename);
        bpf_object__close(*obj);
        return -1;
    }

    return 0;
}


void cleanup(int ifindex,int prog_fd,int check_fd, int map_fd)
{
    //Unload everything and unpin the map too
    if (ifindex) {
        struct bpf_xdp_attach_opts *opts;
        ret = bpf_xdp_detach(ifindex, XDP_FLAGS_SKB_MODE, NULL);
        // ret = bpf_set_link_xdp_fd(ifindex, -1, 0); //Old way of detaching
        if (ret < 0) {
            fprintf(stderr, "Failed to detach xdp_prog from interface: %s\n", strerror(-ret));
        }
    }
    if (prog_fd) {
        close(prog_fd);
    }

#ifndef DEBUG
    if (check_fd) {
        close(check_fd);
    }
    if (map_fd) {
        close(map_fd);
    }
    const char* pin_path = "/sys/fs/bpf/bar";
    if(remove(pin_path))
    {
        fprintf(stderr,"Failed to unpin\n");
    }
    close(dev_fd);
#endif
    printf("Cleaned up and exiting\n");
    exit(0);

}
void signal_handler(int signum)
{
    printf("\nCaught signal, cleanup function called\n");
    cleanup(ifindex,prog_fd_prog, prog_fd_check, map_fd);
}

int main() {
    struct bpf_object *obj_prog = NULL, *obj_check = NULL;
    struct bpf_program *prog_prog, *prog_check;
    struct bpf_map *prog_array_map;

    // Load main XDP program object
    if (load_bpf_object_file("xdp_prog.o", &obj_prog)) {
        return 1;
    }

    //Find the main XDP program by the FUNCTION NAME. In the older versions of libbpf, this was done by section name
    prog_prog = bpf_object__find_program_by_name(obj_prog,"xdp_prog");
    if (!prog_prog) {
        fprintf(stderr, "Failed to find program section in xdp_prog.o\n");
        return 1;
    }

    // Get file descriptor for the main program
    prog_fd_prog = bpf_program__fd(prog_prog);
    if (prog_fd_prog < 0) {
        fprintf(stderr, "Failed to get program file descriptor for xdp_prog.o\n");
        return 1;
    }

#ifndef DEBUG
    // Load the tail called XDP program
    if (load_bpf_object_file("xdp_check.o", &obj_check)) {
        return 1;
    }
    
    // Find the tail called XDP program by the FUNCTION NAME. In the older versions of libbpf, this was done by section name
    prog_check = bpf_object__find_program_by_name(obj_check,"check");
    if (!prog_check) {
        fprintf(stderr, "Failed to find program section in xdp_check.o\n");
        return 1;
    }

    // Get file descriptor for the tail called program
    prog_fd_check = bpf_program__fd(prog_check);
    if (prog_fd_check < 0) {
        fprintf(stderr, "Failed to get program file descriptor for xdp_check.o\n");
        return 1;
    }


    // Find the program array map in xdp_prog.o
    prog_array_map = bpf_object__find_map_by_name(obj_prog, PROG_ARRAY_MAP_NAME);
    if (!prog_array_map) {
        fprintf(stderr, "Failed to find prog_array map in xdp_prog.o\n");
        return 1;
    }
    
    //Get the file descriptor for the map
    map_fd = bpf_map__fd(prog_array_map);
    if (map_fd < 0) {
        fprintf(stderr, "Failed to get map file descriptor for prog_array\n");
        return 1;
    }

    //Pin the map, otherwise the tail call won't work. Get more information on:
    //https://patchwork.ozlabs.org/project/netdev/patch/1544795761-3879-4-git-send-email-quentin.monnet@netronome.com/
    const char* pin_path = "/sys/fs/bpf/bar"; 
    // You can change the name "bar" with anything you want. If you do so, you should change it in the cleanup function too
    if(bpf_map__pin(prog_array_map, pin_path))
    {
        fprintf(stderr,"Failed to pin\n");
        return 1;
    }

    // Update prog_array to include xdp_check.o's program in the tail call
    int key = 0;  // tail call index (adjust as necessary)
    ret = bpf_map_update_elem(map_fd, &key, &prog_fd_check, BPF_ANY);
    if (ret) {
        fprintf(stderr, "Failed to update program_array with xdp_check program\n");
        return 1;
    }
#endif

    ifindex = if_nametoindex("enp0s9");  // Replace with your interface name
    if (ifindex == 0) {
        fprintf(stderr, "Failed to get ifindex for the interface\n");
        return 1;
    }

#ifdef DEBUG
    dev_fd = open("/sys/kernel/btf/dnm_driver", O_RDONLY);
    printf("dev_fd: %d\n",dev_fd);
    char log_buf[100];

    struct bpf_insn insn = {
        .code = BPF_LDX,
        .dst_reg = BPF_REG_8,
        .src_reg = 0,
        .off = 0,
        .imm = 0,
    };

    int fd_arr[1] = {dev_fd};
    struct bpf_prog_load_opts oppts = {
        .kern_version = KERNEL_VERSION(6, 8, 0),
        .sz = sizeof(struct bpf_prog_load_opts),
        .expected_attach_type = BPF_XDP,
        .fd_array = fd_arr,
        .prog_btf_fd = prog_fd_prog,
        .prog_flags = 0,
        .prog_ifindex = ifindex,
        .log_buf = log_buf,
        .log_size = sizeof(log_buf),
        .log_level = 2,
    };
    ret = bpf_prog_load(BPF_PROG_TYPE_XDP,"xdp_prog","GPL",&insn,sizeof(insn),&oppts);
    if (ret < 0) {
        printf("log: %s\n",log_buf);
        printf("Failed to load xdp_prog: %s\n", strerror(-ret));
        cleanup(ifindex,prog_fd_prog, prog_fd_check, map_fd);
        return 1;
    }
#endif

#ifndef DEBUG
    // Attach the main XDP program to an interface
    struct bpf_xdp_attach_opts *opts;

    ret = bpf_xdp_attach(ifindex, prog_fd_prog, XDP_FLAGS_SKB_MODE, opts); // Runs on generic mode
    // ret = bpf_set_link_xdp_fd(ifindex, prog_fd_prog, XDP_FLAGS_SKB_MODE); // Old way of attaching
    if (ret < 0) {
        printf("Failed to attach xdp_prog to interface: %s\n", strerror(-ret));
        cleanup(ifindex,prog_fd_prog, prog_fd_check, map_fd);
        return 1;
    }
#endif
    printf("XDP programs loaded and tail call set up successfully.\n");

    signal(SIGINT, signal_handler);

    // Keep the programs running
    while (1) {
        pause();
    }
    
    return 0;
}

