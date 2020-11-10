#include <linux/syscalls.h>

asmlinkage int kill_hook(struct pt_regs *regs);

extern asmlinkage int (*kill_orig)(struct pt_regs *);
