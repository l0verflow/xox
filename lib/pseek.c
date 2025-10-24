#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/uaccess.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/pid.h>

#include "../include/pseek.h"

#define DEVICE_NAME "pseek"
#define CLASS_NAME  "pseek_class"

static int    major_number;
static struct class* pseek_class   = NULL;
static struct device* pseek_device = NULL;
static struct cdev pseek_cdev;

/* elixir.bootlin.com/linux/v6.17.4/source/include/linux/sched.h#L1084 */
static struct task_struct *target_task = NULL;

static struct task_struct *find_task_by_pid_safe(pid_t pid)
{ /* Find the task_struct for a given PID 
*/
  struct task_struct *task;
  struct pid         *pid_struct;
    
  rcu_read_lock();
  pid_struct = find_vpid(pid);
  if (pid_struct)
    task = pid_task(pid_struct, PIDTYPE_PID);
  else
    task = NULL;
    
  if (task)
    get_task_struct(task);
  rcu_read_unlock();
    
  return task;
}

static int k_pseek_attach(pid_t pid)
{ /* Attach to a process given its PID
*/
  printk(KERN_INFO "XoX <(trying to attach to PID %d)\n", pid);

  if (target_task)
    {
      printk(KERN_WARNING "XoX <(already attached to another process)\n");
      return -EBUSY;
    }

  target_task = find_task_by_pid_safe(pid);
  if (!target_task)
    {
      printk(KERN_WARNING "XoX <(process %d not found)\n", pid);
      return -ESRCH;
    }

  if (send_sig_info(SIGSTOP, SEND_SIG_PRIV, target_task) < 0)
    {
      printk(KERN_WARNING "XoX <(failed to send SIGSTOP)\n");
      put_task_struct(target_task);
      target_task = NULL;
      return -EPERM;
    }

  printk(KERN_INFO "XoX <(attached to process '%s' (PID: %d)\n", target_task->comm, pid);
  return 0;
}

static int k_pseek_detach(void)
{ /* Detach from the currently attached process
*/
  if (!target_task) return -ESRCH;

  printk(KERN_INFO "XoX <(Detaching from the PID process %d)\n", target_task->pid);

  /* elixir.bootlin.com/linux/v6.17.4/source/kernel/signal.c#L892 */
  send_sig_info(SIGCONT, SEND_SIG_PRIV, target_task);

  put_task_struct(target_task);
  target_task = NULL;
  return 0;
}

/*
 * Mockcode
 */

static int access_target_memory(struct pseek_mem_args *args, int write)
{ /* Read or write memory of the attached process (NOT WORKING)
*/
  void __user *user_buf = (void __user *)args->user_buffer;
  char *k_buf;
  int result = 0;

  if (!target_task) return -ESRCH;

  k_buf = kmalloc(args->len, GFP_KERNEL);
  if (!k_buf)
    return -ENOMEM;

  if (write)
    {
      if (copy_from_user(k_buf, user_buf, args->len))
        {
          result = -EFAULT;
          goto out;
        }
      result = args->len;
    }
  else
    {
      memset(k_buf, 0xAA, args->len);
      if (copy_to_user(user_buf, k_buf, args->len))
        {
          result = -EFAULT;
          goto out;
        }
      result = args->len;
    }

out:
  kfree(k_buf);
  return result;
}

static long pseek_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{ /* Handle ioctl commands
*/
  if (!target_task && cmd != P_ATTACH)
    return -ESRCH;

  switch (cmd)
    {
      case P_ATTACH:
            pid_t pid;
            if (copy_from_user(&pid, (pid_t __user *)arg, sizeof(pid)))
                return -EFAULT;
            return k_pseek_attach(pid);

      case P_DETACH:
            return k_pseek_detach();

      case P_GETREGS:
            struct pseek_regs regs;
            struct pt_regs *task_regs = task_pt_regs(target_task);
            if (!task_regs) return -EFAULT;
            
            memset(&regs, 0, sizeof(regs));
            regs.r15 = task_regs->r15;
            regs.r14 = task_regs->r14;
            regs.r13 = task_regs->r13;
            regs.r12 = task_regs->r12;
            regs.r11 = task_regs->r11;
            regs.r10 = task_regs->r10;
            regs.r9 = task_regs->r9;
            regs.r8 = task_regs->r8;
            regs.rax = task_regs->ax;
            regs.rcx = task_regs->cx;
            regs.rdx = task_regs->dx;
            regs.rsi = task_regs->si;
            regs.rdi = task_regs->di;
            regs.rbp = task_regs->bp;
            regs.rsp = task_regs->sp;
            regs.rip = task_regs->ip;

            if (copy_to_user((void __user *)arg, &regs, sizeof(regs)))
                return -EFAULT;
            return 0;

      case P_SETREGS:
            struct pseek_regs regs;
            struct pt_regs *task_regs = task_pt_regs(target_task);
            if (!task_regs) return -EFAULT;

            if (copy_from_user(&regs, (void __user *)arg, sizeof(regs)))
                return -EFAULT;

            task_regs->r15 = regs.r15;
            task_regs->r14 = regs.r14;
            task_regs->r13 = regs.r13;
            task_regs->r12 = regs.r12;
            task_regs->r11 = regs.r11;
            task_regs->r10 = regs.r10;
            task_regs->r9 = regs.r9;
            task_regs->r8 = regs.r8;
            task_regs->ax = regs.rax;
            task_regs->cx = regs.rcx;
            task_regs->dx = regs.rdx;
            task_regs->si = regs.rsi;
            task_regs->di = regs.rdi;
            task_regs->bp = regs.rbp;
            task_regs->sp = regs.rsp;
            task_regs->ip = regs.rip;
            return 0;

      case P_READMEM:
            struct pseek_mem_args args;
            if (copy_from_user(&args, (void __user *)arg, sizeof(args)))
                return -EFAULT;
            return access_target_memory(&args, 0);

      case P_WRITEMEM:
            struct pseek_mem_args args;
            if (copy_from_user(&args, (void __user *)arg, sizeof(args)))
                return -EFAULT;
            return access_target_memory(&args, 1);
  
      default:
            return -ENOTTY;
      }
}

static struct file_operations fops = {
    .owner = THIS_MODULE,
    .unlocked_ioctl = pseek_ioctl,
};

static int __init pseek_init(void)
{
  if (alloc_chrdev_region(&major_number, 0, 1, DEVICE_NAME) < 0)
    {
      printk(KERN_ALERT "XoX <(Failed to allocate major number)\n");
      return -1;
    }

  pseek_class = class_create(CLASS_NAME);
  if (IS_ERR(pseek_class))
    {
      unregister_chrdev_region(major_number, 1);
      printk(KERN_ALERT "XoX <(Failed to register device class)\n");
      return PTR_ERR(pseek_class);
    }

  pseek_device = device_create(pseek_class, NULL, MKDEV(major_number, 0), NULL, DEVICE_NAME);
  if (IS_ERR(pseek_device))
    {
      class_destroy(pseek_class);
      unregister_chrdev_region(major_number, 1);
      printk(KERN_ALERT "XoX <(Failed to create device)\n");
      return PTR_ERR(pseek_device);
    }

  cdev_init(&pseek_cdev, &fops);
  if (cdev_add(&pseek_cdev, MKDEV(major_number, 0), 1) < 0)
    {
      device_destroy(pseek_class, MKDEV(major_number, 0));
      class_destroy(pseek_class);
      unregister_chrdev_region(major_number, 1);
      printk(KERN_ALERT "XoX <(Failed to add cdev)\n");
      return -1;
    }

  printk(KERN_INFO "XoX <(Module loaded. Device created at /dev/pseek)\n");
  return 0;
}

static void __exit pseek_exit(void)
{
  if (target_task) k_pseek_detach();
    
  cdev_del(&pseek_cdev);
  device_destroy(pseek_class, MKDEV(major_number, 0));
  class_destroy(pseek_class);
  unregister_chrdev_region(major_number, 1);
  printk(KERN_INFO "XoX <(Module unloaded)\n");
}

module_init(pseek_init);
module_exit(pseek_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("XoX");
MODULE_VERSION("1.0");
