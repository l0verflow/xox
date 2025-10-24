<p align="center">
	 <img src="https://i.pinimg.com/originals/f9/76/f0/f976f054182dcd795dcd10e4247b7d53.gif"/>
	<i><u></br>XoX</i></u>
</p>

### Tasklist
- [ ] Ftrace for hooking
- [X] Rewrite ptrace for stealth process injection

# X. Hooking

## X.X Ftrace

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
