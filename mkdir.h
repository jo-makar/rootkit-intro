#include <linux/syscalls.h>

asmlinkage int mkdir_hook(struct pt_regs *regs);

extern asmlinkage int (*mkdir_orig)(struct pt_regs *);
