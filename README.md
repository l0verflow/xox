<p align="center">
	 <img align="right" src="https://i.pinimg.com/originals/f9/76/f0/f976f054182dcd795dcd10e4247b7d53.gif"/>
	<i><u></br>XoX</i></u>
</p>

### Tasklist
- [ ] Rewrite ptrace for stealth process injection

# X. Process Injection

## X.X Rewriting ptrace() 


<p align="center">
	<img width="518" height="211" alt="image" src="https://github.com/user-attachments/assets/81f9e40a-3fd5-41c1-8db2-f470f206161d" />
	<i><u></br>https://elixir.bootlin.com/linux/v6.17.4/source/kernel/pid.c#L442</i></u>
</p>

In the kernel the function `find_get_task_by_vpid` finds the `task_struct` for a given `vid`, pinning it in memory with a reference count to prevent it from disappearing while in use.

<p align="center">
	<img width="510" height="300" alt="image" src="https://github.com/user-attachments/assets/1af714a4-0b45-448b-a341-dcf4b14eb71d" />
	<i><u></br>https://elixir.bootlin.com/linux/v6.17.4/source/kernel/ptrace.c#L409</u></i>
</p>

The essence is to force a process to stop by sending it a `SIGSTOP`.
