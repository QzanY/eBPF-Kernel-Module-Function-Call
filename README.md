I have a problem.\
Here xdp_prog.c and xdp_check.c are XDP programs and xdp_prog tail calls xdp_check with a prog_array. This isn't related to my problem.
In my eBPF program(xdp_prog.c), I want to call the function put_31_haha function(which just returns the number 31) of the kernel module defined in dnm-driver.c. I define the function in the beginning of the kernel module and register it in the end of custom_init function. This particular function is not important. All I need is to just call a kernel module function in an eBPF program.\
In order to do this, I know that I need to put the BTF fd of the kernel module to fd_array when BPF_PROG_LOAD is called with bpf syscall however I couldn't figure out how to do it.\
I know there is a function called bpf_prog_load in libbpf but I don't know how to use it in my case since there are absolutely NO RESOURCES explaining how to use this function.
I searched other ways to change fd_array but I couldn't find anything.
