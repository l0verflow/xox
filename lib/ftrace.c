#include "../include/ftrace.h"
#include <linux/module.h>
#include <linux/kernel.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,7,0)
struct kprobe kp = {
    .symbol_name = "kallsyms_lookup_name"
};
#endif

int f_hook_addr(struct ftrace_hook *hook)
{
#ifdef KPROBE_LOOKUP
  typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
  kallsyms_lookup_name_t kallsyms_lookup_name;
  register_kprobe(&kp);
  kallsyms_lookup_name = (kallsyms_lookup_name_t) kp.addr;
  unregister_kprobe(&kp);
#endif
  hook->addr = kallsyms_lookup_name(hook->name);

  if (!hook->addr)
    {
      printk(KERN_DEBUG "XoX <(unresolved symbol: %s)\n", hook->name);
      return -ENOENT;
    }

#if USE_FENTRY_OFFSET
  *((unsigned long*) hook->og) = hook->addr + MCOUNT_INSN_SIZE;
#else
  *((unsigned long*) hook->og) = hook->addr;
#endif

  return 0;
}

void notrace f_thunk(unsigned long ip, unsigned long parent_ip, 
                     struct ftrace_ops *ops, struct ftrace_regs *fregs)
{
  struct ftrace_hook *hook = container_of(ops, struct ftrace_hook, ops);
  struct pt_regs *regs     = ftrace_get_regs(fregs);

  if (!regs)
    return;

#if USE_FENTRY_OFFSET
  regs->ip = (unsigned long) hook->func;
#else
  if(!within_module(parent_ip, THIS_MODULE))
    regs->ip = (unsigned long) hook->func;
#endif
}

int f_install_hook(struct ftrace_hook *hook)
{
  int err;
    
  err = f_hook_addr(hook);
  if(err)
    return err;

  hook->ops.func = f_thunk;
  hook->ops.flags = FTRACE_OPS_FL_SAVE_REGS
          | FTRACE_OPS_FL_RECURSION
          | FTRACE_OPS_FL_IPMODIFY;

  err = ftrace_set_filter_ip(&hook->ops, hook->addr, 0, 0);
  if(err)
    {
      printk(KERN_DEBUG "XoX <(ftrace_set_filter_ip() failed: %d)\n", err);
      return err;
    }

  err = register_ftrace_function(&hook->ops);
  if(err)
    {
      printk(KERN_DEBUG "XoX <(register_ftrace_function() failed: %d)\n", err);
      return err;
    }

  return 0;
}

void f_remove_hook(struct ftrace_hook *hook)
{
  int err;
    
  err = unregister_ftrace_function(&hook->ops);
  if(err)
    printk(KERN_DEBUG "XoX <(unregister_ftrace_function() failed: %d)\n", err);

  err = ftrace_set_filter_ip(&hook->ops, hook->addr, 1, 0);
  if(err)
    printk(KERN_DEBUG "XoX <(ftrace_set_filter_ip() failed: %d)\n", err);
}

int f_install_hooks(struct ftrace_hook *hooks, size_t count)
{
  int err;
  size_t i;

  for (i = 0; i < count; i++)
    {
      err = f_install_hook(&hooks[i]);
      if(err)
        goto error;
    }
  return 0;

error:
  while (i != 0)
      f_remove_hook(&hooks[--i]);

  return err;
}

void f_remove_hooks(struct ftrace_hook *hooks, size_t count)
{
  size_t i;

  for (i = 0; i < count; i++)
    f_remove_hook(&hooks[i]);
}

MODULE_LICENSE("GPL");
MODULE_AUTHOR("XoX");
