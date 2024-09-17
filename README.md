# Kernel Module Function Call from eBPF Program
In this project, I demonstrate calling a kernel module function from an eBPF program.\
The eBPF program and its loader is in eBPF_program folder and the kernel module code is in kernel_module folder.\
My kernel version is 6.8.0
## Kernel Module
dnm-driver.c is a simple kernel module which has read/write and ioctl functions. In the beginning of the module there is also a function named **put_num_haha**. It just returns the number 32. My goal was to call this function from the eBPF program.\
In order to do that we need to register the function as a kfunc. You can see how I did that in the code.\
The load the code, first you compile it with the command `make` in the "kernel" directory.\
If it says it didn't generate BTF due to lack of vmlinux, you should create a symbolic link to the vmlinux file and then install dwarves package.\
vmlinux file is usually located in /sys/kernel/btf folder. You need to create a symbolic link at /lib/modules/$(uname -r)/build with:
```bash
sudo ln -s /sys/kernel/btf/vmlinux /lib/modules/$(uname -r)/build
```
Then install the dwarves package. You can do that in Ubuntu with:
```bash
sudo apt install dwarves
```
Then you can load it to the kernel with:
```bash
sudo insmod dnm-driver.ko
```
## eBPF Program
xdp_prog.c is a simple XDP program which checks the packets for some certain attributes. It makes a tail call to xdp_check.c if encounters a ICMP packet.\
To call the put_num_haha function, first you need to spesify that it is an extern function with `__kysm` suffix as I did in the code.\
Then you can call it in the code anywhere. Then you can load the program to the kernel with prog_load.c which is a loader program I wrote with libbpf.\
You don't need to do anything to include put_num_haha function here because bpf_object__load() function does everything for you.(It populates the fd_array parameter in bpf() syscall with the BTF fd of the kernel module you are using)\
You can compile the code with:
```bash
./compile
```
Then you can load the XDP program with:
```bash
sudo ./loader
```
## Test it
First load the kernel module, then load the eBPF program. Then on another terminal, do:
```bash
sudo cat /sys/kernel/tracing/trace_pipe
```
If you send packets to the machine on which you run the code, you will see what is happenning.

