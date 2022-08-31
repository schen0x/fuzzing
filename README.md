# fuzzing

## TABLE OF CONTENTS

- [fuzzing](#fuzzing)
  - [TABLE OF CONTENTS](#table-of-contents)
  - [ANGR](#angr)
    - [ANGR CUSTOM SETUP](#angr-custom-setup)
    - [ANGR-TOP LEVEL INTERFACES](#angr-top-level-interfaces)
    - [ANGR-LOADING A BINARY](#angr-loading-a-binary)
    - [ANGR-SOLVER ENGINE](#angr-solver-engine)
    - [ANGR-PROGRAM STATE](#angr-program-state)
    - [ANGR-SIMULATION MANAGERS](#angr-simulation-managers)

## ANGR

- [angr doc](https://docs.angr.io/core-concepts)

### ANGR CUSTOM SETUP

```sh
sudo apt-get install python3-dev libffi-dev build-essential virtualenv ipython
virtualenv --python=$(which python3) ~/local/angr
echo -e 'source /home/<user>/local/angr/bin/activate\n' > ~/.local/bin/angr

source angr
pip install angr monkeyhex
```

### ANGR-TOP LEVEL INTERFACES

```py
ipython3
import angr
import claripy
import monkeyhex                             # print int as hex in ipython
p = angr.Project('/bin/true', auto_load_libs=False)
hex(p.entry)
p.arch.name
p.arch.bits
p.arch.bytes
p.loader.shared_objects
p.loader.main_object

# ==== [BASIC BLOCK] ====
block = p.factory.block(p.entry)
block.pp()                                   # pretty print in asm
block.capstone.pp()
block.vex.pp()

# ==== [STATE INIT] ====
state = p.factory.entry_state                # <SimState @hex(p.entry)>

# ==== [STATE && BITVECTOR] ====
# Bit Vectors Values are used to simulator data in the memory/CPU reg
# e.g. they wrap on overflow
# help(state.solver) # The `solver` is the claripy plugin, which is used to interact with symbolic variables, creating them and evaluating them.
bv = state.solver.BVV(0x1234, 32)            # create a bitvector <BV32 0x1234>
state.solver.eval(bv)                        # 0x1234
state.regs.rsi                               # <BV64 0x7fffffffffeff90>
state.regs.rsi = state.solver.BVV(3, 64)     # -> <BV64 0x3>
state.mem[0x1000].long = 4                   # modify state mem
# state.mem[addr].<type>.resolved            # get the value as a bitvector
# state.mem[addr].<type>.concrete            # get the value as a python int
state.mem[0x1000].long.resolved              # <BV64 0x4>
state.mem[0x1000].long.concrete              # 0x4

# ==== [SIMULATION MANAGER] ====
simgr = proj.factory.simulation_manager(state)
  # <SimulationManager with 1 active>
simgr.active                                 # [<SimState @ 0x4023c0>]
simgr.active[0]                              # <SimState @ 0x4023c0>
simgr.step()                 # a basic block's worth of execution!
# The original 'state' is immutable
state                                        # <SimState @ 0x4023c0>
simgr.active[0]                              # <SimState @ 0x527720>
simgr.active[0].regs.rip                     # <BV64 0x527720>
simgr.active[0].solver.eval(simgr.active[0].regs.rip) # 0x527720
state.solver.eval(simgr.active[0].regs.rip)           # 0x527720

# ==== [ANALYSES] ====
proj.analyses.*
# Originally, when we loaded this binary it also loaded all its dependencies into the same virtual address  space
# This is undesirable for most analysis.
proj = angr.Project('/bin/true', auto_load_libs=False)
cfg = proj.analyses.CFGFast()
cfg.graph
```

### ANGR-LOADING A BINARY

```py
# ipython3
import angr, claripy, monkeyhex
p = angr.Project('simple-file-read')
p.loader.find_object_containing(p.entry)
  # <ELF Object simple-file-read, maps [0x400000:0x40408f]>
p.loader.find_symbol('strcmp')
  # <Symbol "strcmp" in libc-2.33.so at 0x58dff0>
p.loader.main_object.plt
strcmp = p.loader.find_symbol('strcmp')
strcmp.name             # 'strcmp'
strcmp.owner            # <ELF Object libc-2.33.so, maps [0x500000:0x6c8377]>
strcmp.rebased_addr     # 0x58dff0
strcmp.linked_addr      # 0x8dff0
strcmp.relative_addr    # (?) in Windows, RVA(Relative Virtual Address)
main_strcmp = p.loader.main_object.get_symbol('strcmp')
  # <Symbol "strcmp" in simple-file-read (import)>
main_strcmp.is_export   # False
main_strcmp.is_import   # True
main_strcmp.resolvedby  # <Symbol "strcmp" in libc-2.33.so at 0x58dff0>
# obj.relocs
p.loader.shared_objects['libc.so.6'].imports  # check the relocs address

# ==== [Symbolic Function Summaries(https://docs.angr.io/core-concepts/loading#symbolic-function-summaries)] ====
# if auto_load_libs is True (this is the default), then the real library function is executed instead.
```

### ANGR-SOLVER ENGINE

- angr can perform arithmetic operations with symbolic variables, yielding an AST.

> ASTs can be translated into constraints for an SMT solver, like z3, in order to ask questions like "given the output of this sequence of operations, what must the input have been?"

```py
import angr, monkeyhex
p = angr.Project('/bin/true')
state = p.factory.entry_state()

# ==== [BITVECTOR] ====
one = state.solver.BVV(1, 64)            # <BV64 0x1>
one_hundred = state.solver.BVV(100, 64)  # <BV64 0x64>
# ==== [ARITHEMETIC with python int] ====
one_hundred + 0x100        # <BV64 0x164>
one_hundred - one * 200    # <BV64 0xffffffffffffff9c>, -100 in 2's compliment

weird_nine = state.solver.BVV(9, 27)
weird_nine.zero_extend(64 - 27)          # <BV64 0x9>, pad to left with 0 bits
weird_nine.sign_extend(64 - 27)          # <BV64 0x9>, left-most bit unchanged
one + weird_nine.zero_extend(64 - 27)

# ==== [BITVECTOR SYMBOL] ====
x = state.solver.BVS("x", 64)            # <BV64 x_90_64>
y = state.solver.BVS("y", 64)            # <BV64 y_91_64>

(x + one - y) / 2 # <BV64 (x_90_64 + 0x1 - y_91_64) / 0x2>, which is an AST

# ==== [AST TREE] ====
tree = (x + one - y) / 2  # <BV64 (x_90_64 + 0x1) / (y_91_64 + 0x2)>

# Each AST has a .op and a .args.
# The op is a string naming the operation being performed,
tree.op                   # '__floordiv__'

# the args are the values the operation takes as input. Unless the op is BVV or BVS (or a few others...), the args are all other ASTs, the tree eventually terminating with BVVs or BVSs.
tree.args                 # (<BV64 x_90_64 + 0x1 - y_91_64>, <BV64 0x2>)
tree.args[0].op           # '__sub__'
tree.args[0].args         # (<BV64 x_90_64 + 0x1>, <BV64 y_91_64>)
# ... the tree ended at 'BVS' or 'BVV'

# ==== [SYMBOLIC CONSTRAINTS] ====
one > -5                  # <Bool False>, by default unsigned
one.SGT(-5)               # <Bool True>, Signed Greater Than
x > 2                     # <Bool x_90_64 > 0x2>
# > you should never directly use a comparison between variables in the condition for an if- or while-statement, since the answer might not have a concrete truth value.
state.solver.is_true(one > -5) # False

# ==== [CONSTRAINTS SOLVING] ====
# > You can treat any symbolic boolean as an assertion about the valid values of a symbolic variable by adding it as a constraint to the state.
# > You can then query for a valid value of a symbolic variable by asking for an evaluation of a symbolic expression.
state.solver.add(x > y)
state.solver.add(y > 2)
state.solver.add(10 > x)
state.solver.eval(x)

# ==== [CONSTRAINTS SOLVING, EXAMPLE] ====
# ipython3
import angr, monkeyhex
p = angr.Project('/bin/true')
state = p.factory.entry_state()
input = state.solver.BVS('input', 64)
operation = (((input + 4) * 3) >> 1) + input
output = 200
state.solver.add(operation == output)
state.solver.eval(input) # 0x3333333333333381
# state.solver.add(input < 2**32)
# state.satisfiable()      # False, if unsat

# fresh state
state = p.factory.entry_state()
state.solver.add(x - y >= 4)
state.solver.add(y > 0)
state.solver.eval(x)      # 5
state.solver.eval(y)      # 1
state.solver.eval(x + y)  # 6
# > From this we can see that `eval` is a general purpose method to convert any bitvector into a python primitive while respecting the integrity of the state.
# > This is why we use eval to convert from concrete bitvectors to python ints, too!

# ==== [FLOATING POINT NUMBERS] ====
# fresh state
state = p.factory.entry_state()
a = state.solver.FPV(3.2, state.solver.fp.FSORT_DOUBLE)
  # <FP64 FPV(3.2, DOUBLE)>
b = state.solver.FPS('b', state.solver.fp.FSORT_DOUBLE)
  # <FP64 FPS('FP_b_0_64', DOUBLE)>
a + b
  # <FP64 fpAdd('RNE', FPV(3.2, DOUBLE), FPS('FP_b_0_64', DOUBLE))>
a + 4.4
  # <FP64 FPV(7.6000000000000005, DOUBLE)>
b + 2 < 0
  # <Bool fpLT(fpAdd('RNE', FPS('FP_b_0_64', DOUBLE), FPV(2.0, DOUBLE)), FPV(0.0, DOUBLE))>
state.solver.add(b + 2 < 0)
state.solver.add(b + 2 > -1)
state.solver.eval(b)
a.raw_to_bv() # get the raw BV representation <BV64 0x400999999999999a>
state.solver.BVV(0, 64).raw_to_fp()
  # <FP64 FPV(0.0, DOUBLE)>, preserves bit pattern
state.solver.BVS('x', 64).raw_to_fp()
  # <FP64 fpToFP(x_44_64, DOUBLE)>, preserves bit pattern
state.solver.eval(a)
  # 3.2
a.val_to_bv(12)
  # <BV12 0x3>, preserve value as close as possible
a.val_to_bv(12).val_to_fp(state.solver.fp.FSORT_FLOAT)
  # <FP32 FPV(3.0, FLOAT)>

# ==== [EXTRA EVAL METHODS] ====
solver.eval(expression)
  # give you one possible solution to the given expression.
solver.eval_one(expression)
  # give you the solution to the given expression, or throw an error if more than one solution is possible.
solver.eval_upto(expression, n)
  # give you up to n solutions to the given expression, returning fewer than n if fewer than n are possible.
solver.eval_atleast(expression, n)
  # give you n solutions to the given expression, throwing an error if fewer than n are possible.
solver.eval_exact(expression, n)
  # give you n solutions to the given expression, throwing an error if fewer or more than are possible.
solver.min(expression)
  # give you the minimum possible solution to the given expression.
solver.max(expression)
  # give you the maximum possible solution to the given expression.
solver.eval(expression, cast_to=[int|bytes])
```

### ANGR-PROGRAM STATE

```py
# ipython
import angr, monkeyhex, claripy
p = angr.Project('./stdin-strcmp', auto_load_libs=False)
arg = claripy.BVS("arg", 8 * 0x20)
state = p.factory.entry_state(args=["./stdin-strcmp", arg])
# TODO
# succ = state.step()
# succ.successors
# ==== [[STATE PRESET](https://docs.angr.io/core-concepts/states#state-presets)]
# [entry_state interface doc](http://angr.io/api-doc/angr.html#angr.factory.AngrObjectFactory)
p.factory.entry_state()
  # constructs a state ready to execute at the main binary's entry point.
p.factory.full_init_state()
  # constructs a state that is ready to execute through any initializers that need to be run before the main binary's entry point, for example, shared library constructors or preinitializers.
p.factory.call_state()
  # constructs a state ready to execute a given function.
state = p.factory.entry_state(args=["./stdin-strcmp", arg])

# data = claripy.BVS('data', 8*32)
# filename = 'angr-simple-file-read-simfile.txt'
# simfile = angr.SimFile(filename, content=data)
state = p.factory.entry_state(args=['./file-read-strcmp', filename], fs={ filename: simfile })
```

### ANGR-SIMULATION MANAGERS

- > allows you to control symbolic execution over groups of states simultaneously, applying search strategies to explore a program's state space.

```py
# ipython3
import angr, monkeyhex, claripy
p = angr.Project('./stdin-strcmp', auto_load_libs=False)
arg = claripy.BVS("arg", 8 * 0x20)
state = p.factory.entry_state(args=["./stdin-strcmp", arg])
simgr = p.factory.simgr(state)
simgr.active    # [<SimState @ 0x401070>]
simgr.step()    # <SimulationManager with 1 active>
simgr.active    # [<SimState @ 0x500000>]
while len(simgr.active) == 1:
    simgr.step()
simgr.active    # [<SimState @ 0x4011a4>, <SimState @ 0x4011cf>]
simgr.run()     # <SimulationManager with 3 deadended>, run till all deadends
simgr.deadended # [<SimState @ 0x601058>, <SimState @ 0x601058>, <SimState @ 0x601058>]
simgr.deadended[0].posix.dumps(1)
# ==== [[STASH TYPES](https://docs.angr.io/core-concepts/pathgroups#stash-types)] ====
# active, deadended, pruned, unconstrained, unsat, errored
```
