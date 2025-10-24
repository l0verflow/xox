#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <string.h>
#include <errno.h>
#include <signal.h>

#include "../include/pseek.h"

#define DEVICE_PATH "/dev/pseek"

void help()
{
  printf("XoX | Use: ./pseek <cmd> [arg]\n"
         "Commands:\n"
         "  attach <pid>           - Attach to the process with the specified PID\n"
         "  detach                 - Detach from the current process\n"
         "  getregs                - Show the registers of the attached process\n"
         "  readmem <addr> <len>   - Read 'len' bytes from the address 'addr'\n"
         "  writemem <addr> <data> - Write data to the specified address\n"
         "  test                   - Execute a basic test\n");
}

void pregs(struct pseek_regs *regs)
{
  printf("RIP: 0x%016llx\n", regs->rip);
  printf("RSP: 0x%016llx\n", regs->rsp);
  printf("RAX: 0x%016llx\n", regs->rax);
  printf("RBX: 0x%016llx\n", regs->rbx);
  printf("RCX: 0x%016llx\n", regs->rcx);
  printf("RDX: 0x%016llx\n", regs->rdx);
  printf("RSI: 0x%016llx\n", regs->rsi);
  printf("RDI: 0x%016llx\n", regs->rdi);
  printf("RBP: 0x%016llx\n", regs->rbp);
}

int main(int argc, char *argv[])
{
  int fd;
  int ret;
    
  if (argc < 2)
    {
      help();
      return 1;
    }
    
  fd = open(DEVICE_PATH, O_RDWR);
  if (fd < 0)
    {
      perror("[\033[31m-\033[0m] Error opening /dev/pseek");
      return 1;
    }
    
  if (strcmp(argv[1], "attach") == 0)
    {
      if (argc != 3)
        {
          printf("XoX | Use: %s attach <pid>\n", argv[0]);
          close(fd);
          return 1;
        }
        
      pid_t pid = atoi(argv[2]);
      printf("[\033[34m*\033[0m] Trying to attach to PID %d\n", pid);
        
      ret = ioctl(fd, P_ATTACH, &pid);
      if (ret < 0)
        {
          perror("[\033[31m-\033[0m] Error attaching to process");
          close(fd);
          return 1;
        }

      printf("[\033[32m+\033[0m] Successfully attached to process PID %d\n", pid);
    }
  else if (strcmp(argv[1], "detach") == 0)
    {
      printf("[\033[34m*\033[0m] Trying to detach from process...\n");
        
      ret = ioctl(fd, P_DETACH);
      if (ret < 0)
        {
          perror("[\033[31m-\033[0m] Error detaching from process");
          close(fd);
          return 1;
        }

      printf("[\033[32m+\033[0m] Successfully detached from process\n");
    }
  else if (strcmp(argv[1], "getregs") == 0)
    {
      struct pseek_regs regs;

      ret = ioctl(fd, P_GETREGS, &regs);
      if (ret < 0)
        {
          perror("[\033[31m-\033[0m] Error obtaining registers");
          close(fd);
          return 1;
        }
        
      pregs(&regs);
    }
  else if (strcmp(argv[1], "readmem") == 0)
    {
      if (argc != 4)
      {
          printf("XoX | Use: %s readmem <addr_hex> <len>\n", argv[0]);
          close(fd);
          return 1;
        }
        
      unsigned long addr = strtoul(argv[2], NULL, 16);
      size_t len = atoi(argv[3]);
        
      if (len > 1024)
        {
          printf("[\033[33m!\033[0m] Limiting read to 1024 bytes\n");
          len = 1024;
        }
        
      char *buffer = malloc(len);
      if (!buffer)
        {
          perror("[\033[31m-\033[0m] Error allocating buffer");
          close(fd);
          return 1;
        }
        
      struct pseek_mem_args args = {
          .pid         = 0,  
          .addr        = addr,
          .user_buffer = (unsigned long)buffer,
          .len         = len
        };

      printf("[\033[34m*\033[0m] Trying to read %zu bytes from address 0x%lx\n", len, addr);

      ret = ioctl(fd, P_READMEM, &args);
      if (ret < 0)
        {
          perror("[\033[31m-\033[0m] Error reading memory");
          free(buffer);
          close(fd);
          return 1;
        }

      printf("[\033[34m*\033[0m] Read %d bytes:\n", ret);
      printf("Hex: ");
      for (int i = 0; i < ret; i++)
        {
          printf("%02x ", (unsigned char)buffer[i]);
          if ((i + 1) % 16 == 0) printf("\n     ");
        }
      printf("\n");
        
      printf("ASCII: ");
      for (int i = 0; i < ret; i++)
        {
          char c = buffer[i];
          printf("%c", (c >= 32 && c <= 126) ? c : '.');
        }
      printf("\n");

      free(buffer);
    }
  else
    {
      printf("[\033[31m-\033[0m] Unknown command: %s\n", argv[1]);
      help();
      close(fd);
      return 1;
    }
    
  close(fd);
  return 0;
}
