#include "mkdir.h"

asmlinkage int (*mkdir_orig)(struct pt_regs *);

asmlinkage int mkdir_hook(struct pt_regs *regs) {
    char __user *pathname_user = (char *)regs->di;
    char pathname_kern[NAME_MAX];

    long rv = strncpy_from_user(pathname_kern, pathname_user, sizeof(pathname_kern));
    if (rv == -EFAULT)
        printk(KERN_WARNING "strncpy_from_user: access to userspace failed");
    else {
        if (rv == sizeof(pathname_kern)) {
            printk(KERN_WARNING "strncpy_from_user: buffer size exceeded");
            pathname_kern[rv - 1] = 0;
        } else
            pathname_kern[rv] = 0;
        printk(KERN_INFO "mkdir %s", pathname_kern);
    }

    return mkdir_orig(regs);
}
