#!/usr/bin/python3  
from bcc import BPF
from bcc.syscall import syscall_name
from time import sleep

program = r"""
BPF_HASH(counter_table);

int hello(struct bpf_raw_tracepoint_args *ctx) {
   u64 syscall_id = ctx->args[1];
   u64 counter = 0;
   u64 *p;

   p = counter_table.lookup(&syscall_id);
   if (p != 0) {
      counter = *p;
   }
   counter++;
   counter_table.update(&syscall_id, &counter);
   return 0;
}
"""

b = BPF(text=program)
syscall = b.get_syscall_fnname("execve")
# b.attach_kprobe(event=syscall, fn_name="hello")

# Attach to a tracepoint that gets hit for all syscalls 
b.attach_raw_tracepoint(tp="sys_enter", fn_name="hello")

while True:
    sleep(2)
    s = ""
    for k,v in b["counter_table"].items():
        s += f"{syscall_name(k.value).decode('utf-8'):>20}: {v.value}\n"
    s += '\n'
    print(s)
