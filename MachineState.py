from capstone.x86 import *

reg_dict = {globals()[d]:d.split('_')[-1] for d in dir() if 'X86_REG_' in d}
def reg_str(reg):
	return reg_dict[reg]

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

class Immediate(object):
	def __init__(self, value):
		self.value = value
	def __eq__(self, other):
		return isinstance(other, type(self)) and self.value == other.value
	def __repr__(self): return 'Immediate({})'.format(self.value)

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