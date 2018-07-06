#! /usr/bin/python

# angr test
# stdin input

import angr
import claripy
from angr import SimFile


invalid_addr = 0x80484eb
goal_addr =  0x80485ff

'''
# old deprecated way
proj = angr.Project('./simple')
pg = proj.factory.path_group()
pg.explore(find = goal_addr, avoid = invalid_addr)
print pg

if len(pg.found) > 0:  
    found = pg.found[0]
    flag = found.state.posix.dumps(0).strip('\0\n')
    print 'flag =', flag
'''
'''
# new way
proj = angr.Project('./simple')
sim_mngr = proj.factory.simgr()
sim_mngr.explore(find = goal_addr, avoid = invalid_addr)
print sim_mngr

if len(sim_mngr.found) > 0:  
    found = sim_mngr.found[0]
    flag = found.state.posix.dumps(0).strip('\0\n')
    print 'flag =', flag
'''
main_addr = 0x804850b

proj = angr.Project('./simple')

#st = proj.factory.entry_state(add_options=angr.options.unicorn)
#st = proj.factory.full_init_state(args=['./simple'], add_options=angr.options.unicorn)
#st = proj.factory.entry_state(args = ['./simple'])
#entry_state = proj.factory.blank_state(addr=main_addr)

# range(8) - sets a boundary for input length
bytes_list = [claripy.BVS('byte_%d' % i, 8) for i in range(8)]
bytes_ast = claripy.Concat(*bytes_list)

#state = proj.factory.entry_state(addr = main_addr, stdin=SimFile('/dev/stdin', content=bytes_ast))
state = proj.factory.entry_state(stdin=SimFile('/dev/stdin', content=bytes_ast))

# setting constraint for first input character to be equals to 'z'
state.add_constraints(bytes_list[0] == claripy.BVV(0x7a, 8))

# setting constraint for all input characters to be printable
#for byte in bytes_list:
#   state.add_constraints(byte >= claripy.BVV(0x20, 8))
#   state.add_constraints(byte <= claripy.BVV(0x7e, 8))

sim_mngr = proj.factory.simgr(state)
sim_mngr.explore(find = goal_addr, avoid = invalid_addr)

if len(sim_mngr.found) > 0:  
    found = sim_mngr.found[0]
    flag = found.state.posix.dumps(0).strip('\0\n')
    print 'flag =', flag


# flag = zyxwv
































