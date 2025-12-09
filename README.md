<p align="center">
	<i><u></br>XoX</i></u>
</p>

### Tasklist
- [X] Ftrace for hooking
- [X] Rewrite ptrace for stealth process injection

# X. Hooking

## X.X Ftrace

To simplify kprobe was used for symbol resolution, while ftrace was used for the entire hooking system.

<p align="center">
	<img width="510" height="220" alt="image"
		src="https://github.com/user-attachments/assets/b14a000c-5589-4de5-acba-5626f19109fa" />
	<i><u></br>https://elixir.bootlin.com/linux/v6.17.5/source/fs/readdir.c#L396</i></u>
</p>

The first step is get the address of the symbols. And we use the `kallsyms_lookup_name` function for this. A tip, if your system is not exporting kallsyms_lookup_name (`kernel.kptr_restrict= 1 | 2`), you can do the following trick:

```c
#ifdef KPROBE_LOOKUP
  typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
  kallsyms_lookup_name_t kallsyms_lookup_name;
  register_kprobe(&kp);
  kallsyms_lookup_name = (kallsyms_lookup_name_t) kp.addr;
  unregister_kprobe(&kp);
#endif
  ...
```

That way, the `kprobe` subsystem is asked to prepare a debug probe at the `kallsyms_lookup_name` function, and the kernel itself is forced to find the address of the function and store it in `kp.addr`.

<p align="center">
	<i><u></br>getdents64()</i></u>
	<br>
	<img width="510" height="250" alt="image"
		src="https://github.com/user-attachments/assets/03154a78-531f-4b0c-b436-43ba122b311f" />
	<i><u></br>https://elixir.bootlin.com/linux/v6.17.5/source/fs/readdir.c#L396</i></u>
</p>



# X. Process Injection

## X.X Rewriting ptrace() 


<p align="center">
	<img width="518" height="211" alt="image"
		src="https://github.com/user-attachments/assets/81f9e40a-3fd5-41c1-8db2-f470f206161d" />
	<i><u></br>https://elixir.bootlin.com/linux/v6.17.4/source/kernel/pid.c#L442</i></u>
</p>

In the kernel the function `find_get_task_by_vpid` finds the `task_struct` for a given `vid`, pinning it in memory with a reference count to prevent it from disappearing while in use.

<p align="center">
	<img width="510" height="300" alt="image"
		src="https://github.com/user-attachments/assets/1af714a4-0b45-448b-a341-dcf4b14eb71d" />
	<i><u></br>https://elixir.bootlin.com/linux/v6.17.4/source/kernel/ptrace.c#L409</u></i>
</p>

The essence is to force a process to stop by sending it a `SIGSTOP`.

<p align="center">
	<img width="510" height="200" alt="image"
		src="https://github.com/user-attachments/assets/2fed4b86-9e60-40ad-94ac-fc2a74b67f17" />
	<i><u></br>https://elixir.bootlin.com/linux/v6.17.4/source/kernel/ptrace.c#L69</u></i>
</p>

The original `ptrace` establishes a parent-child relationship using `__ptrace_link`, but this implementation can be simplified by defining a global variable to maintain control instead.



<p align="center">
  <img align="left" width="510" height="200" alt="image"
       src="https://github.com/user-attachments/assets/252b85a0-c1db-463e-843e-3bde9fe8c029" />
  <img align="right" width="510" height="200" alt="image"
       src="https://github.com/user-attachments/assets/60847f3f-7c5b-4242-83ed-e1c9ce215d90" />
</p>

<br clear="both">

<p align="center">
  <i><u></br>
    <a href="https://elixir.bootlin.com/linux/v6.17.4/source/kernel/ptrace.c#L117">
      https://elixir.bootlin.com/linux/v6.17.4/source/kernel/ptrace.c#L117
    </a>
  </u></i>
</p>

In the kernel `__ptrace_unlink`, it directly breaks the parent-child link and wakes up the process through an internal scheduler call, but we can send signals like a `SIGCONT` event to emulate the wake up effect in a more generic way.


<p align="center">
	<img width="510" height="350" alt="image"
		src="https://github.com/user-attachments/assets/01fdc4f7-1f57-47a1-a000-f9cc6740987d" />
	<i><u></br>https://elixir.bootlin.com/linux/v6.17.4/source/arch/alpha/kernel/ptrace.c#L277</u></i>
</p>

The kernel `arch_ptrace` is designed to access the saved registers of a stopped process.

<p align="center">
	<img width="510" height="500" alt="image"
		src="https://github.com/user-attachments/assets/2ab89d08-e24d-44f0-ba0b-6406c8666f14" />
	<i><u></br>https://elixir.bootlin.com/linux/v6.17.4/source/mm/memory.c#L6686</u></i>
</p>


In the kernel `__access_remote_vm`, it reads/writes memory by mapping the target physical page into the kernel own address space (`kmap`) and then using `copy_from` and`to_user_page` functions, whereas a simpler implementation might use a direct memcpy on that mapped address.
