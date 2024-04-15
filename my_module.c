#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/uaccess.h>

#define DEVICE_NAME "my_device"
#define BUF_LEN 4096

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Your Name");
MODULE_DESCRIPTION("A simple character device module");

static int major;
static char *data_buffer;

static int device_open(struct inode *inode, struct file *file) {
    return 0;
}

static int device_release(struct inode *inode, struct file *file) {
    return 0;
}

static ssize_t device_read(struct file *file, char __user *buffer, size_t length, loff_t *offset) {
    return simple_read_from_buffer(buffer, length, offset, data_buffer, BUF_LEN);
}

static ssize_t device_write(struct file *file, const char __user *buffer, size_t length, loff_t *offset) {
    return simple_write_to_buffer(data_buffer, BUF_LEN, offset, buffer, length);
}

static const struct file_operations fops = {
    .owner = THIS_MODULE,
    .open = device_open,
    .release = device_release,
    .read = device_read,
    .write = device_write,
};

static int __init my_module_init(void) {
    major = register_chrdev(0, DEVICE_NAME, &fops);
    if (major < 0) {
        printk(KERN_ALERT "Failed to register a major number\n");
        return major;
    }
    printk(KERN_INFO "Registered correctly with major number %d\n", major);

    data_buffer = kmalloc(BUF_LEN, GFP_KERNEL);
    if (!data_buffer) {
        unregister_chrdev(major, DEVICE_NAME);
        printk(KERN_ALERT "Failed to allocate memory\n");
        return -ENOMEM;
    }
    memset(data_buffer, 0, BUF_LEN);

    return 0;
}

static void __exit my_module_exit(void) {
    kfree(data_buffer);
    unregister_chrdev(major, DEVICE_NAME);
    printk(KERN_INFO "Module unloaded\n");
}

module_init(my_module_init);
module_exit(my_module_exit);
