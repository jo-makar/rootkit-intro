#include <linux/syscalls.h>

asmlinkage int getdents64_hook(struct pt_regs *regs);

extern asmlinkage int (*getdents64_orig)(struct pt_regs *regs);
