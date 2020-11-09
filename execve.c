#include "execve.h"

asmlinkage int (*execve_orig)(struct pt_regs *);

asmlinkage int execve_hook(struct pt_regs *regs) {
    char __user *filename_user = (char *)regs->di;
    char filename_kern[NAME_MAX];

    long rv = strncpy_from_user(filename_kern, filename_user, sizeof(filename_kern));
    if (rv == -EFAULT)
        printk(KERN_WARNING "strncpy_from_user: access to userspace failed");
    else {
        if (rv == sizeof(filename_kern)) {
            printk(KERN_WARNING "strncpy_from_user: buffer size exceeded");
            filename_kern[rv - 1] = 0;
        } else
            filename_kern[rv] = 0;
        printk(KERN_INFO "execve %s ...", filename_kern);
    }

    return execve_orig(regs);
}
