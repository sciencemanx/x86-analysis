from ForwardAnalysis import ForwardAnalysis
from CFG import CFG, op_str
from pwnlib.elf import ELF
from capstone.x86 import *
from Enumeration import Enumeration

lattice = Enumeration("top bottom")

class EspAnalysis(ForwardAnalysis):
	def empty_state(self):
		return lattice.bottom

	def merge(self, s1, s2):
		if s1 is lattice.bottom:
			return s2
		if s2 is lattice.bottom:
			return s1
		else:
			if s1 == s2:
				return s1
			else:
				return lattice.top

	def flow_func(self, state, op):
		if state in [lattice.top, lattice.bottom]:
			return state
		if op.id == X86_INS_POP:
			state += 8
		if op.id == X86_INS_PUSH:
			state -= 8
		return state


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
