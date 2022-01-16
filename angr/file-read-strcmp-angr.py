import angr
import claripy

p = angr.Project('./file-read-strcmp', main_opts={'base_addr': 0}, auto_load_libs=False)

def correct(state):
    try:
        return b'good job!' in state.posix.dumps(1)
    except:
        return False

def wrong(state):
        try:
            return b'wrong' in state.posix.dumps(1)
        except:
            return False

data = claripy.BVS('data', 8*32)
filename = 'angr-simple-file-read-simfile.txt'
simfile = angr.SimFile(filename, content=data)

state = p.factory.entry_state(args=['./file-read-strcmp', filename], fs={ filename: simfile })
sm = p.factory.simulation_manager(state)


print("start exploration")
sm.explore(find=correct, avoid=wrong)

print("len(simgr.found) = {}".format(len(sm.found)))

if len(sm.found) > 0:
    s = sm.found[0]
    print("stdout = {!r}".format(s.posix.dumps(1)))
    print(s.solver.eval(data, cast_to=bytes))
