#! /usr/bin/python

# command line argument input 
# if wrong input - program exits with code 0x2a (42)
# if success flag is displayed and operation is made using the key to decode an URL
# 11th character should be *
# 12th character should be A in order for the decoding to work and the argument should be 16 characters long


import angr
import claripy
import logging
import binascii

#from pwn import *
#s = process(argv = ['./chall', '\x69\x6e\x73\x6f\x6d\x6e\x69\x68\x61\x63\x6b\x2a\x41\x0b\x16\x99'])
#s.interactive()


#logging.getLogger('angr').setLevel('DEBUG')
logging.getLogger('angr.sim_mananger').setLevel(logging.DEBUG)


# 0x00400bdc      e805fcffff     call sym.calc_offset
calc_offset_call = 0x00400bdc

# addresses of the blocks to avoid
# 0x00400ad3      bf33000000     mov edi, 0x33
# 0x00400b12      bf2a000000     mov edi, 0x2a
# 0x00400b3c      bf2a000000     mov edi, 0x2a
# 0x00400bbd      bf2a000000     mov edi, 0x2a
# 0x00400c05      bf2a000000     mov edi, 0x2a 
avoid_arr = [0x00400ad3, 0x00400b12, 0x00400b3c, 0x00400bbd, 0x00400c05]
goal_addr =  0x00400c0f

# in souce chall.c calc_offset functions returns 137 always
def calc_offset(state):
  state.regs.rax = state.se.BVV(137, 8 * 8)

proj = angr.Project('./chall')

# script stucks without this hook
# When setting a hook the number of bytes to overwrite should be given (ex: 5 for a call instruction on x86). 
# If the value is 0 then the initial instruction is not replaced but the hook gets called before it
proj.hook(calc_offset_call, calc_offset, length = 5)

arg1 = claripy.BVS('arg1', 16 * 8)
entry_state = proj.factory.entry_state(args=['./chall', arg1])

for c in arg1.chop(8):
    entry_state.add_constraints(c != 0)

entry_state.add_constraints(arg1.get_byte(11) == claripy.BVV(0x2a, 8))   # *
entry_state.add_constraints(arg1.get_byte(12) == claripy.BVV(0x41, 8))   # A
entry_state.add_constraints(arg1.get_byte(15) == claripy.BVV(0x99, 8))   


simngr = proj.factory.simgr(entry_state)
simngr.explore(find = goal_addr, avoid = avoid_arr)

#print [method_name for method_name in dir(object) if callable(getattr(object, method_name))]

if len(simngr.found) > 0:
    found = simngr.found[0]  
    #flag = found.state.se.any_str(arg1) # old deprecated way
    flag = found.state.se.eval(arg1, cast_to=str)
    print [flag] # ['insomnihack*A\x0b\x16\x99']
    # print binascii.hexlify(flag) # 696e736f6d6e696861636b2a410b1699 



# ./chall $(python -c "print 'insomnihack*A\x0b\x16\x99'") 
# flag is : 4-d55178613463f133d89c1593e122f5524c45153db3d2f03989667ef05fcc73026ad884
# Now go to :
# http://
# www.insomnihack.ch/3e01460b5548c25403f8ec432594029ca38b6b7c6133d4e7f6aeae4807db4e3db2
# ca7ab34f485c7f283b9cf0f67e83488218d2d2c39c896af7ff30490c960756/

 




