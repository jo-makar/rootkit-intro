#include "hook.h"

#include <linux/syscalls.h>

// Ref: /usr/share/doc/kernel-doc-$(uname -r | cut -d- -f1)/Documentation/output/trace/ftrace-uses.html
//      https://movaxbx.ru/2018/10/12/hooking-linux-kernel-functions-how-to-hook-functions-with-ftrace/
//          especially "Unexpected surprised when using ftrace"

static void hook_callback(unsigned long ip, unsigned long parent_ip, struct ftrace_ops *ops, struct pt_regs *regs);

int hook_init(struct hook *hook) {
    int err;
    unsigned long rv;

    rv = kallsyms_lookup_name(hook->name);
    hook->orig = (void *)rv;
    if (rv == 0) {
        printk(KERN_ERR "unresolved symbol: %s", hook->name);
        return -ENOENT;
    }

    if (hook->orig_ptr != NULL)
        *hook->orig_ptr = hook->orig;

    hook->ops.func = hook_callback;

    // Hijacking requires modifying the rip register so SAVE_REGS and IPMODIFY are necessary.
    // Modifying rip makes the recursion protection useless, disable with RECURSION_SAFE.
    // Alternate recursion protection handled internally by hook_callback.
    //
    // Another approach to avoid recursion is by jumping over the ftrace call,
    // by adding MCOUNT_INSN_SIZE to the values of hook->orig and *hook->orig_ptr.

    hook->ops.flags = FTRACE_OPS_FL_SAVE_REGS | FTRACE_OPS_FL_IPMODIFY | FTRACE_OPS_FL_RECURSION_SAFE;

    if ((err = ftrace_set_filter_ip(&hook->ops, (unsigned long)hook->orig, 0, 0)) != 0) {
        printk(KERN_ERR "ftrace_set_filter_ip failed: %d", err);

        hook->orig = 0;
        if (hook->orig_ptr != NULL)
            *hook->orig_ptr = 0;

        return err;
    }

    if ((err = register_ftrace_function(&hook->ops)) != 0) {
        printk(KERN_ERR "register_ftrace_function failed: %d", err);

        ftrace_set_filter_ip(&hook->ops, (unsigned long)hook->orig, 1, 0);
        hook->orig = 0;
        if (hook->orig_ptr != NULL)
            *hook->orig_ptr = 0;

        return err;
    }

    return 0;
}

void hook_deinit(struct hook *hook) {
    int err;

    if (hook->orig == 0)
        return;

    if ((err = unregister_ftrace_function(&hook->ops)) != 0)
        printk(KERN_ERR "unregister_ftrace_function failed: %d", err);

    if ((err = ftrace_set_filter_ip(&hook->ops, (unsigned long)hook->orig, 1, 0)) != 0)
        printk(KERN_ERR "ftrace_set_filter_ip failed: %d", err);

    hook->orig = 0;
    if (hook->orig_ptr != NULL)
        *hook->orig_ptr = 0;
}

static void notrace hook_callback(unsigned long ip, unsigned long parent_ip, struct ftrace_ops *ops, struct pt_regs *regs) {
    // Given a pointer to a struct member refer back to the containing struct.
    // This callback is always called with the struct ftrace_ops arg from the register_ftrace_function call.
    // Ref: https://www.linuxjournal.com/files/linuxjournal.com/linuxjournal/articles/067/6717/6717s2.html
    struct hook *hook = container_of(ops, struct hook, ops);

    if (within_module(parent_ip, THIS_MODULE))
        printk(KERN_WARNING "%s hook: recursive call detected, not applying hook", hook->name);
    else
        regs->ip = (unsigned long)hook->func;
}
