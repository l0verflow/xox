#ifndef PSEEK_IOCTL_H
#define PSEEK_IOCTL_H

#include <linux/ioctl.h>
#include <linux/types.h>

struct pseek_mem_args {
    __u64 pid;
    __u64 addr;
    __u64 user_buffer;
    __u64 len;
};

struct pseek_regs {
    __u64 r15, r14, r13, r12, r11, r10, r9, r8;
    __u64 rax, rcx, rdx, rbx, rsp, rbp, rsi, rdi;
    __u64 rip, cs, eflags, rsp_orig, ss;
    __u64 fs_base, gs_base;
    __u64 ds, es, fs, gs;
};

#define PSEEK_MAGIC 'P'

#define P_ATTACH   _IOW (PSEEK_MAGIC, 1, pid_t)
#define P_DETACH   _IO  (PSEEK_MAGIC, 2)
#define P_GETREGS  _IOR (PSEEK_MAGIC, 3, struct pseek_regs)
#define P_SETREGS  _IOW (PSEEK_MAGIC, 4, struct pseek_regs)
#define P_READMEM  _IOWR(PSEEK_MAGIC, 5, struct pseek_mem_args)
#define P_WRITEMEM _IOW (PSEEK_MAGIC, 6, struct pseek_mem_args)

#endif // PSEEK_H_
