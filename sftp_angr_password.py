#! /usr/bin/python

#from pwn import *
import angr
import claripy
import logging
from angr import SimFile

func_addr = 0x4013F0
correct_pass_addr = 0x401531

logging.getLogger('angr.sim_mananger').setLevel(logging.DEBUG)

proj = angr.Project('./sftp')

bytes_list = [claripy.BVS('byte_%d' % i, 8) for i in range(8)]
bytes_ast = claripy.Concat(*bytes_list)

entry_state = proj.factory.entry_state(addr = func_addr, stdin=SimFile('/dev/stdin', content=bytes_ast))

entry_state.add_constraints(bytes_list[3] == claripy.BVV(0x53, 8))
entry_state.add_constraints(bytes_list[4] == claripy.BVV(0x74, 8))
entry_state.add_constraints(bytes_list[5] == claripy.BVV(0x65, 8))

for byte in bytes_list:
   entry_state.add_constraints(byte >= claripy.BVV(0x41, 8))
   entry_state.add_constraints(byte != claripy.BVV(0x60, 8))
   entry_state.add_constraints(byte <= claripy.BVV(0x7e, 8))

simgr = proj.factory.simgr(entry_state)
simgr.explore(find = correct_pass_addr)

print [simgr.found[0].state.posix.dumps(0)]
# ['yesm\x05\xa2\x01\xff\x00\x01\x01\x01\x01\x01\x01\x01\x01\x01'] wothput constraints
# ['yesAPABIBPAfPpaBDuPPPPPPPPPPPPPP'] with constraints
