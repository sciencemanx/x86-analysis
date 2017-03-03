from ForwardAnalysis import ForwardAnalysis
from MachineState import MachineState, Immediate, StackPointer
from CFG import CFG, op_str
from pwnlib.elf import ELF
from capstone.x86 import *
from Enumeration import Enumeration
from copy import deepcopy

class Unknown(object):
	def __eq__(self, other):
		return isinstance(other, type(self))
	def __repr__(self): return 'Unknown()'

def merge_data(d1, d2):
	if d1 == d2:
		return d1
	else:
		return Unknown()

def merge_dict(d1, d2, merge):
	overlapping_keys = set(d1) & set(d2)
	merged = {}
	for key in set(d1) - overlapping_keys:
		merged[key] = d1[key]
	for key in set(d2) - overlapping_keys:
		merged[key] = d2[key]
	for key in overlapping_keys:
		merged[key] = merge(d1[key], d2[key])
	return merged



class VariableAnalysis(ForwardAnalysis):
	def empty_state(self):
		return MachineState()

	def merge(self, s1, s2):
		new_state = MachineState()
		new_state.regs = merge_dict(s1.regs, s2.regs, merge_data)
		new_state.memory = merge_dict(s1.memory, s2.memory, merge_data)
		return new_state

	def flow_func(self, state, op):
		new_state = deepcopy(state)

		if op.id == X86_INS_PUSH:
			rsp_val = state.regs[X86_REG_RSP]
			if isinstance(rsp_val, StackPointer):
				rsp_val = StackPointer(rsp_val.addr - 8)
			else:
				rsp_val = Unknown()
			new_state.regs[X86_REG_RSP] = rsp_val

		if op.id == X86_INS_POP:
			rsp_val = state.regs[X86_REG_RSP]
			if isinstance(rsp_val, StackPointer):
				rsp_val = StackPointer(rsp_val.addr + 8)
			else:
				rsp_val = Unknown()
			new_state.regs[X86_REG_RSP] = rsp_val

		if op.id == X86_INS_MOV:
			dst, src = op.operands
			val = state.read_value(src)
			new_state.store_value(dst, val)

		if op.id == X86_INS_SUB:
			dst, src = op.operands
			op_1 = state.read_value(dst)
			op_2 = state.read_value(src)
			if isinstance(op_1, Immediate) and isinstance(op_2, Immediate):
				val = Immediate(op_1.value - op_2.value)
			else:
				val = Unknown()
			new_state.store_value(dst, val)

		if op.id == X86_INS_ADD:
			dst, src = op.operands
			op_1 = state.read_value(dst)
			op_2 = state.read_value(src)
			if isinstance(op_1, Immediate) and isinstance(op_2, Immediate):
				val = Immediate(op_1.value + op_2.value)
			else:
				val = Unknown()
			new_state.store_value(dst, val)

		if op.id == X86_INS_AND:
			dst, src = op.operands
			op_1 = state.read_value(dst)
			op_2 = state.read_value(src)
			if isinstance(op_1, Immediate) and isinstance(op_2, Immediate):
				val = Immediate(op_1.value & op_2.value)
			else:
				val = Unknown()
			new_state.store_value(dst, val)

		return new_state


if __name__ == '__main__':
	import sys

	if len(sys.argv) != 2:
		print('Usage: {} <file>'.format(sys.argv[0]))
		sys.exit()

	e = ELF(sys.argv[1])
	main_addr = e.symbols['main']

	cfg = CFG(e, main_addr)
	start = MachineState()
	start.regs[X86_REG_RSP] = StackPointer(0)

	vars = VariableAnalysis(cfg, entry_state=start)
	for op_addr in sorted(cfg.ops):
		op = cfg.ops[op_addr]
		print('{:120s} -- {}'.format(vars.before_states[op], op_str(op)))
