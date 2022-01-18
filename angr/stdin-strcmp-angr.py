import angr
import claripy


def correct(state):
    try:
        return b"good job!" in state.posix.dumps(1)
    except:
        return False


def wrong(state):
    try:
        return b"wrong" in state.posix.dumps(1)
    except:
        return False


proj = angr.Project("./stdin-strcmp", main_opts={"base_addr": 0}, auto_load_libs=False)
arg = claripy.BVS("arg", 8 * 0x20)

state = proj.factory.entry_state(args=["./stdin-strcmp", arg])

simgr = proj.factory.simulation_manager(state)
# simgr.explore(find=0x11be, avoid=[0x11cf]) # OK
# simgr.explore(find=correct, avoid=wrong)  # OK
simgr.explore(find=lambda s: b"good job!" in s.posix.dumps(1), avoid=wrong)  # OK
print("len(simgr.found) = {}".format(len(simgr.found)))

if len(simgr.found) > 0:
    s = simgr.found[0]
    print("argv[1] = {!r}".format(s.solver.eval(arg, cast_to=bytes)))
    print("stdin = {!r}".format(s.posix.dumps(0)))

# src: [https://gist.github.com/inaz2/c812671841f97804c24ba6650b1b2500]
# gcc stdin-strcmp.c -o stdin-strcmp

# (gdb) disassemble main
# Dump of assembler code for function main:
#    0x0000000000001159 <+0>:     push   %rbp
#    0x000000000000115a <+1>:     mov    %rsp,%rbp
#    0x000000000000115d <+4>:     sub    $0x40,%rsp
#    0x0000000000001161 <+8>:     mov    %edi,-0x34(%rbp)
#    0x0000000000001164 <+11>:    mov    %rsi,-0x40(%rbp)
#    0x0000000000001168 <+15>:    lea    -0x30(%rbp),%rax
#    0x000000000000116c <+19>:    mov    %rax,%rsi
#    0x000000000000116f <+22>:    lea    0xe8e(%rip),%rax        # 0x2004
#    0x0000000000001176 <+29>:    mov    %rax,%rdi
#    0x0000000000001179 <+32>:    mov    $0x0,%eax
#    0x000000000000117e <+37>:    call   0x1050 <__isoc99_scanf@plt>
#    0x0000000000001183 <+42>:    mov    -0x40(%rbp),%rax
#    0x0000000000001187 <+46>:    add    $0x8,%rax
#    0x000000000000118b <+50>:    mov    (%rax),%rax
#    0x000000000000118e <+53>:    lea    0xe74(%rip),%rdx        # 0x2009
#    0x0000000000001195 <+60>:    mov    %rdx,%rsi
#    0x0000000000001198 <+63>:    mov    %rax,%rdi
#    0x000000000000119b <+66>:    call   0x1040 <strcmp@plt>
#    0x00000000000011a0 <+71>:    test   %eax,%eax
#    0x00000000000011a2 <+73>:    jne    0x11cf <main+118>
#    0x00000000000011a4 <+75>:    lea    -0x30(%rbp),%rax
#    0x00000000000011a8 <+79>:    lea    0xe63(%rip),%rdx        # 0x2012
#    0x00000000000011af <+86>:    mov    %rdx,%rsi
#    0x00000000000011b2 <+89>:    mov    %rax,%rdi
#    0x00000000000011b5 <+92>:    call   0x1040 <strcmp@plt>
#    0x00000000000011ba <+97>:    test   %eax,%eax
#    0x00000000000011bc <+99>:    jne    0x11cf <main+118>
#    0x00000000000011be <+101>:   lea    0xe5b(%rip),%rax        # 0x2020
#    0x00000000000011c5 <+108>:   mov    %rax,%rdi
#    0x00000000000011c8 <+111>:   call   0x1030 <puts@plt>
#    0x00000000000011cd <+116>:   jmp    0x11de <main+133>
#    0x00000000000011cf <+118>:   lea    0xe54(%rip),%rax        # 0x202a
#    0x00000000000011d6 <+125>:   mov    %rax,%rdi
#    0x00000000000011d9 <+128>:   call   0x1030 <puts@plt>
#    0x00000000000011de <+133>:   mov    $0x0,%eax
#    0x00000000000011e3 <+138>:   leave
#    0x00000000000011e4 <+139>:   ret
# End of assembler dump.
