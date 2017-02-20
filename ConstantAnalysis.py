from ForwardAnalysis import ForwardAnalysis
from CFG import CFG, op_str
from pwnlib.elf import ELF
from capstone.x86 import *
from Enumeration import Enumeration
from copy import deepcopy

reg_dict = {globals()[d]:d.split('_')[-1] for d in dir() if 'X86_REG_' in d}
def reg_str(reg):
	return reg_dict[reg]

op_ = None

class StackPointer(object):
	def __init__(self, addr=0):
		self.addr = addr
	def __eq__(self, other):
		if isinstance(other, type(self)):
			return self.addr == other.addr
		return False
	def __hash__(self):
		return hash(self.addr)
	def __repr__(self):
		return 'SP({})'.format(self.addr)

class NonPointer(object):
	def __eq__(self, other):
		return isinstance(other, type(self))
	def __repr__(self): return 'NonPointer()'

class Immediate(object):
	def __init__(self, value):
		self.value = value
	def __eq__(self, other):
		return isinstance(other, type(self)) and self.value == other.value
	def __repr__(self): return 'Immediate({})'.format(self.value)

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

class MachineState(object):
	def __init__(self):
		self.memory = {}
		self.regs = {}
	def __eq__(self, other):
		if isinstance(other, type(self)):
			return self.regs == other.regs and self.memory == other.memory
		return False
	def __ne__(self, other):
		return not (self == other)
	def __hash__(self):
		return hash(self.addr)
	def __repr__(self):
		return "Machine(regs:{}, mem:{})".format(
			{reg_str(r):v for r,v in self.regs.items()}, self.memory)
	def store_value(self, operand, value):
		if operand.type == X86_OP_REG:
			self.regs[operand.reg] = value
		if operand.type == X86_OP_MEM:
			mem = operand.mem
			base_addr = self.regs[mem.base].addr
			addr = base_addr + mem.disp + (mem.index * mem.scale)
			self.memory[StackPointer(addr)] = value
	def read_value(self, operand):
		if operand.type == X86_OP_IMM:
			return Immediate(operand.imm)
		if operand.type == X86_OP_REG:
			return self.regs[operand.reg]
		if operand.type == X86_OP_MEM:
			mem = operand.mem
			base_addr = self.regs[mem.base].addr
			addr = base_addr + mem.disp + (mem.index * mem.scale)
			return self.memory[StackPointer(addr)]

class VariableAnalysis(ForwardAnalysis):
	def empty_state(self):
		return MachineState()

	def merge(self, s1, s2):
		new_state = MachineState()
		new_state.regs = merge_dict(s1.regs, s2.regs, merge_data)
		new_state.memory = merge_dict(s1.memory, s2.memory, merge_data)
		# print('merging {} and {} to {}'.format(s1, s2, new_state))
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
