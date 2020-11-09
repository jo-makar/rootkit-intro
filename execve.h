#include <linux/syscalls.h>

asmlinkage int execve_hook(struct pt_regs *regs);

extern asmlinkage int (*execve_orig)(struct pt_regs *);
