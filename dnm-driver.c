#include <linux/init.h>
#include <linux/module.h>
#include <linux/uaccess.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/atomic.h>
#include <linux/cdev.h>
#include <linux/delay.h>
#include <linux/device.h>
#include <linux/types.h>
#include <linux/printk.h>
#include <linux/btf.h>

#include "dnm-driver.h"

// Module metadata
MODULE_AUTHOR("Ozan Yanik");
MODULE_DESCRIPTION("Hello world driver");
MODULE_LICENSE("GPL");

/*
If you want use arguments when you load this module with insmod:
module_param(varName, type, permissions(put 0))

static int a = 1;
module_param(a,int,0);

static int myArray[2];
static int count;
module_param_array(myArray,int,count,0);
*/

__bpf_kfunc_start_defs();

__bpf_kfunc int put_31_haha(void) 
{
    return 32;
}

__bpf_kfunc_end_defs();

BTF_SET8_START(btf_kfunc_id_set)
BTF_SET8_END(btf_kfunc_id_set)

static const struct btf_kfunc_id_set kfunc_id_set = {
    .owner = THIS_MODULE,
    .set = &btf_kfunc_id_set,
    .filter = NULL,
};


static int device_open(struct inode*, struct file*);
static int device_release(struct inode *, struct file *);
static ssize_t device_read(struct file *, char __user *, size_t, loff_t *);
static ssize_t device_write(struct file *, const char __user *, size_t, loff_t *);
static long device_ioctl(struct file* file, unsigned int ioctl_num, unsigned long ioctl_param);

#define SUCCESS 0
#define DEVICE_NAME "denemedevice" 
#define BUF_LEN 80

static struct cdev dev_cdev;
static int major;

static int usr_buf_len;

/* To determine if our driver is being used */
enum
{
    CDEV_NOT_USED = 0,
    CDEV_EXCLUSIVE_OPEN = 1,
};

/*
typedef struct {
	int counter;
} atomic_t;

Atomic types are used in atomic functions.
Atomic functions are the functions those are completed in just one CPU cycle 
so that nothing can interrupt them and cause data races.
*/
static atomic_t already_open = ATOMIC_INIT(CDEV_NOT_USED);

/* 
The msg the device will give when asked. Actually, this is the main functionality of our driver. 
We read from and write to this variable. 
*/
static char msg[BUF_LEN + 1]; 


/*
 A class is a higher-level view of a device that abstracts out low-level
 implementation details. Drivers may see a SCSI disk or an ATA disk, but,
 at the class level, they are all simply disks. Classes allow user space
 to work with devices based on what they do, rather than how they are
 connected or how they work.
*/
static struct class *cls;

static struct file_operations chardev_fops = {
    .owner = THIS_MODULE,
    .read = device_read,
    .write = device_write,
    .open = device_open,
    .release = device_release,
    .unlocked_ioctl = device_ioctl,
};

static int __init custom_init(void)
{
    // dev is the device number which consists of major and minor numbers.
    dev_t dev = MKDEV(100,0);
    int alloc_ret = -1;
    int cdev_ret = -1;

    // If you want to dynamically allocate the major number you this function instead of register_chrdev_region
    // alloc_ret = alloc_chrdev_region(&dev, 0, 1, DEVICE_NAME);
    
    /**
     * register_chrdev_region() - register a range of device numbers
     * @from: the first in the desired range of device numbers; must include
     *        the major number.
     * @count: the number of consecutive device numbers required
     * @name: the name of the device or driver.
     *
     * Return value is zero on success, a negative error code on failure.
     */
    alloc_ret = register_chrdev_region(dev, 1, DEVICE_NAME);

    if (alloc_ret < 0 )
        goto error;

    cls = class_create(DEVICE_NAME);

    
    major = MAJOR(dev);

    device_create(cls, NULL, MKDEV(major, 0), NULL, DEVICE_NAME);

    cdev_init(&dev_cdev, &chardev_fops);
    cdev_ret = cdev_add(&dev_cdev, dev, 1);

    if (cdev_ret)
        goto error;

    pr_info("I was assigned major number %d.\n", major);
    pr_info("Device created on /dev/%s\n", DEVICE_NAME);

    register_btf_kfunc_id_set(BPF_PROG_TYPE_XDP, &kfunc_id_set);
    
    return SUCCESS;

error:
    if (alloc_ret < 0)
        unregister_chrdev_region(dev, 1);

    if (cdev_ret == 0)
    {   
        device_destroy(cls, MKDEV(major,0));
        cdev_del(&dev_cdev);
    }
    return -1;
}

static void __exit custom_exit(void)
{
    pr_info("Device removed\n");
    dev_t dev = MKDEV(major, 0);
    cdev_del(&dev_cdev);
    device_destroy(cls, MKDEV(major,0));
    class_destroy(cls);
    unregister_chrdev_region(dev, 1);

}

/*
    - try_module_get(THIS_MODULE): Increment the reference count of current
    module.
    - module_put(THIS_MODULE): Decrement the reference count of current
    module.
    - module_refcount(THIS_MODULE): Return the value of reference count of
    current module.
*/

/* 
    Called when a process tries to open the device file, like
    sudo cat /dev/chardev"
*/
static int device_open(struct inode* inode, struct file* file)
{
    static int counter = 0;

    // Compare v with old, if they are equal put new at v, else do nothing
    // Returns the old value
    // Here it means give error if the device is being used already
    // if (atomic_cmpxchg(&already_open, CDEV_NOT_USED, CDEV_EXCLUSIVE_OPEN))
    //     return -EBUSY;

    // Writes the sentence to msg.
    sprintf(msg, "I already told you %d times Hello world!\n", counter++);

    /*
    This is the Right Way to get a module: if it fails, it's being removed,
    so pretend it's not there.
    */
    try_module_get(THIS_MODULE);

    return SUCCESS;
}

/* Called when a process closes the device file. */
static int device_release(struct inode *inode, struct file *file)
{
    /* We're now ready for our next caller */
    atomic_set(&already_open, CDEV_NOT_USED);

    // Decrement the usage count, or else once you opened the file, you will never get rid of the module.
    module_put(THIS_MODULE);

    return SUCCESS;
}

/* Called when a process, which already opened the dev file, attempts to read from it. */
static ssize_t device_read(struct file *filp,
                           char __user *buffer,
                           size_t length,
                           loff_t* offset)
{

//   !!! IMPORTANT : The content of msg is written in the open method with sprintf, here we put it to the user buffer  !!!

    pr_info("READ FUNCTION CALLED\n");
    /* Number of bytes actually written to the buffer */
    int bytes_read = 0;

    const char* msg_ptr = msg;

    /* we are at the end of message */
    if (!*(msg_ptr+ (*offset)))
    {
        *offset = 0;   /* reset the offset */
        return 0;      /* signify end of file */
    }

    msg_ptr += *offset;

    /* Actually put the data into the buffer */
    while (length && *msg_ptr) {
    /* 
        The buffer is in the user data segment, not the kernel
        segment so "*" assignment won't work. We have to use
        put_user which copies data from the kernel data segment to
        the user data segment.
    */
    /*
      put_user - Write a simple value into user space.
      @x:   Value to copy to user space.
      @ptr: Destination address, in user space.
      Context: User context only. This function may sleep if pagefaults are
               enabled.

      This macro copies a single simple value from kernel space to user
      space.  It supports simple types like char and int, but not larger
      data types like structures or arrays.

      @ptr must have pointer-to-simple-variable type, and @x must be assignable
      to the result of dereferencing @ptr.
     
      Return: zero on success, or -EFAULT on error.
     */
        put_user(*(msg_ptr++), buffer++);
        length--;
        bytes_read++;
    }

    *offset += bytes_read;

    /* Most read functions return the number of bytes put into the buffer. */
    return bytes_read;
}

/* Called when a process writes to dev file: echo "hi" > /dev/hello */
static ssize_t device_write(struct file *filp, const char __user *buff, size_t len, loff_t *off)
{
    pr_info("Device write called!");
    if (len > BUF_LEN)
        len = BUF_LEN;
    if (copy_from_user(msg,buff,len))
    {
        pr_alert("Cannot write the user input!");
        return -EINVAL;    
    }
    msg[len] = '\0';
    if (off)
        *off += len;

    pr_info("Received from user: %s\n",msg);
    
    return len;
    
}


/* This function is called whenever a process tries to do an ioctl on our
   device file. We get two extra parameters (additional to the inode and file
   structures, which all device functions get): the number of the ioctl
   called and the parameter given to the ioctl function.
  
   If the ioctl is write or read/write (meaning output is returned to the
   calling process), the ioctl call returns the output of this function.
*/
static long device_ioctl(struct file* file,
                         unsigned int ioctl_num,
                         unsigned long ioctl_param)
{
    pr_info("Trying ioctl!!!!!");
    int i;
    long ret = SUCCESS;

    if (atomic_cmpxchg(&already_open, CDEV_NOT_USED, CDEV_EXCLUSIVE_OPEN))
        return -EBUSY;

    switch (ioctl_num)
    {
    case IOCTL_SET_MSG: {
        pr_info("IOCTL SETTING MESSAGE");
        /* Receive a pointer to a message (in user space) and set that to
        * be the device's message. Get the parameter given to ioctl by
        * the process.
        */
        char __user *tmp = (char __user *)ioctl_param;
        char ch;
        /* Find the length of the message */
        get_user(ch, tmp);
        for (i = 0; ch && i < BUF_LEN; i++, tmp++)
            get_user(ch, tmp);

        device_write(file, (char __user *)ioctl_param, i, NULL);
        break;
    }
    
    case IOCTL_GET_MSG: {
        loff_t offset = 0;

        /* Give the current message to the calling process - the parameter
        * we got is a pointer, fill it.
        */
        i = device_read(file, (char __user *)ioctl_param, usr_buf_len-1, &offset);

        /* Put a zero at the end of the buffer, so it will be properly
        * terminated.
        */
        put_user('\0', (char __user*)ioctl_param + i);
        break;
    }

    case IOCTL_GET_NTH_BYTE:
        /* This ioctl is both input (ioctl_param) and output (the return
        * value of this function).
        */
        ret = (long)msg[ioctl_param];
        break;

    case IOCTL_SET_LENGTH:
        //Get the length of the user's buffer;

        usr_buf_len = ioctl_param;
        pr_info("Got the length %d",usr_buf_len);
        break;
    }



    atomic_set(&already_open, CDEV_NOT_USED);

    return ret;

}


module_init(custom_init);
module_exit(custom_exit);
