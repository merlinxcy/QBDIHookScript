#!/usr/bin/env python2
# -*- coding: utf-8 -*-

import pyqbdi

def mycb(vm, gpr, fpr, data):
    inst = vm.getInstAnalysis()
    reg = vm.getGPRState()
    print("=====================Register==============")
    print("RAX",reg.rax)
    print("RBX",reg.rbx)
    print("RCX",reg.rcx)
    print("RIP",reg.rip)
    #print(vm.getGPRState().rip)#rip,rax,rdx
    #print(vm.getGPRState().rip)#rip,rax,rdx
    #print(vm.getInstMemoryAccess())
    #print(vm.getBBMemoryAccess())
    print "0x%x: %s" % (inst.address, inst.disassembly)
    return pyqbdi.CONTINUE

def test_memory_access(vm,gpr,fpr,data):
    print("memory access")

def pyqbdipreload_on_run(vm, start, stop):
    print(hex(start),hex(stop))
    #指令
    vm.addCodeCB(pyqbdi.PREINST, mycb, None)
    #vm.addCodeAddrCB(0x555555555020,pyqbdi.PREINST,mycb,None)
    #vm.addCodeRangeCB(0x555555555020,0x555555555139,pyqbdi.PREINST,mycb,None)
    #内存
    # test memory access function
    #vm.addMemAccessCB(pyqbdi.MEMORY_READ_WRITE,test_memory_access,None)
    #vm.addMemAddrCB(0x6004,pyqbdi.MEMORY_READ_WRITE,test_memory_access,None)
    #vm.recordMemoryAccess(pyqbdi.MEMORY_READ_WRITE)
    #Helper
    #print(pyqbdi.readMemory(0x555555556004,4))
    #pyqbdi.writeMemory(0x555555556004,"321")
    vm.run(start, stop)
