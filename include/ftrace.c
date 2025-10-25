#ifndef FTRACE_H
#define FTRACE_H

#include <linux/ftrace.h>
#include <linux/linkage.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/version.h>

#if defined(CONFIG_X86_64) && (LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0))
#define PTREGS_SYSCALL_STUBS 1
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,7,0)
#define KPROBE_LOOKUP 1
  #include <linux/kprobes.h>
    extern struct kprobe kp;
#endif

#define HOOK(_name, _hook, _orig)   \
{                                   \
    .name     = (_name),            \
    .func = (_hook),                \
    .og       = (_orig),            \
}

#define USE_FENTRY_OFFSET 0
  #if !USE_FENTRY_OFFSET
  #pragma GCC optimize("-fno-optimize-sibling-calls")
#endif

struct ftrace_hook {
    const char *name;
    void       *func;
    void       *og;
  
    unsigned long addr;
    struct ftrace_ops ops;
};

int f_hook_addr (struct ftrace_hook *hook);

void notrace f_thunk (unsigned long ip, unsigned long parent_ip,
                      struct ftrace_ops *ops, struct ftrace_regs *regs);

int  f_install_hook (struct ftrace_hook *hook);
void f_remove_hook  (struct ftrace_hook *hook);

int  f_install_hooks(struct ftrace_hook *hooks, size_t count);
void f_remove_hooks (struct ftrace_hook *hooks, size_t count);

#endif // FTRACE_H
