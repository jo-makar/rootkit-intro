#include <linux/ftrace.h>

struct hook {
    const char *name;       // Expected to be in .rodata
    void *orig;             // Also used to indicate successful init
    void **orig_ptr;        // For use within callback
    void *func;
    struct ftrace_ops ops;
};

int hook_init(struct hook *hook);
void hook_deinit(struct hook *hook);

