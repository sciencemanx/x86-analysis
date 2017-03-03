from ForwardAnalysis import ForwardAnalysis
from CFG import CFG, op_str
from pwnlib.elf import ELF
from capstone.x86 import *
from Enumeration import Enumeration

lattice = Enumeration("top bottom")

class EspAnalysis(ForwardAnalysis):
	def empty_state(self):
		return (lattice.bottom, lattice.bottom, ())

	def merge(self, s1, s2):
		def m(s1, s2):
			if s1 is lattice.bottom:
				return s2
			if s2 is lattice.bottom:
				return s1
			else:
				if s1 == s2:
					return s1
				else:
					return lattice.top

		return tuple(m(a,b) for a,b in zip(s1,s2))

	def flow_func(self, state, op):
		def flow_esp(esp):
			if esp in [lattice.top, lattice.bottom]:
				return esp
			if op.id in [X86_INS_POP, X86_INS_RET, X86_INS_LEAVE]:
				esp += 8
			if op.id in [X86_INS_PUSH, X86_INS_CALL]:
				esp -= 8
			if op.id == X86_INS_SUB and op.operands[0].reg == X86_REG_RSP:
				esp -= op.operands[1].imm
			if op.id == X86_INS_ADD and op.operands[0].reg == X86_REG_RSP:
				esp += op.operands[1].imm
			return esp

		(esp, ebp), stack = state

		if op.id == X86_INS_MOV and op.operands[0].type == X86_OP_REG and op.operands[1].type == X86_OP_REG:
			if op.operands[0].reg == X86_REG_RSP and op.operands[1].reg == X86_REG_RBP:
				esp = ebp
			if op.operands[0].reg == X86_REG_RBP and op.operands[1].reg == X86_REG_RSP:
				ebp = esp
		if op.id == X86_INS_LEAVE:
			esp = ebp
		if op.id == X86_INS_POP and op.operands[0].type == X86_OP_REG and op.operands[0].reg == X86_REG_RBP:
			if len(stack) != 0:
				ebp = stack[0]
				stack = stack[1:]
			else:
				ebp = lattice.top
		if op.id == X86_INS_PUSH and op.operands[0].type == X86_OP_REG and op.operands[0].reg == X86_REG_RBP:
			stack = (ebp,) + stack

		return ((flow_esp(esp), ebp), stack)

	def show_state(self, op, state):
		print('{}: esp = {}'.format(op_str(op), hex(state[0][0])))


if __name__ == '__main__':
	import sys

	if len(sys.argv) != 2:
		print('Usage: {} <file>'.format(sys.argv[0]))
		sys.exit()

	e = ELF(sys.argv[1])
	main_addr = e.symbols['main']

	cfg = CFG(e, main_addr)
	esp = EspAnalysis(cfg, entry_state=0)
	for op_addr in sorted(cfg.ops):
		op = cfg.ops[op_addr]
		print('{} -- esp = {}'.format(op_str(op), esp.before_states[op]))
