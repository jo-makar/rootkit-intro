#include <linux/syscalls.h>

asmlinkage ssize_t random_read_hook(struct file *file, char __user *buf, size_t nbytes, loff_t *ppos);
asmlinkage ssize_t urandom_read_hook(struct file *file, char __user *buf, size_t nbytes, loff_t *ppos);

extern asmlinkage ssize_t (*random_read_orig)(struct file *file, char __user *buf, size_t nbytes, loff_t *ppos);
extern asmlinkage ssize_t (*urandom_read_orig)(struct file *file, char __user *buf, size_t nbytes, loff_t *ppos);
