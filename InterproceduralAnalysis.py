from CFG import CFG
from pwnlib.elf import ELF
from capstone.x86 import *
from CallGraph import CallGraph

# dynamically subclasses analysis function to use do interprocedural analysis
def patch_analysis(Analysis, call):
	def flow_func(self, state, op):
		out_state = Analysis.flow_func(self, state, op)
		if op.id == X86_INS_CALL:
			if op.operands[0].type != X86_OP_IMM:
				raise Exception('only direct calls supported')
			return call(op.operands[0].imm, out_state)
		else:
			return out_state

	class_name = 'Interprocedural{}'.format(Analysis.__name__)

	return type(class_name, (Analysis,), {'flow_func': flow_func})

class InterproceduralAnalysis(object):
	def __init__(self, elf, start, Analysis, entry_state=None):
		self.call_graph = CallGraph(elf, start)
		self.Analysis = patch_analysis(Analysis, self.call)
		self.analyses = {} # map from context (call address, state) to state
		self.call(start, entry_state)

	def call(self, addr, state):
		if (addr, state) not in self.analyses:
			cfg = self.call_graph[addr]
			analysis = self.Analysis(cfg, entry_state=state)
			self.analyses[(addr, state)] = analysis
		return self.analyses[(addr, state)].after_states[cfg.end]


if __name__ == '__main__':
	import sys
	from EspAnalysis import EspAnalysis, lattice

	if len(sys.argv) != 2:
		print('Usage: {} <file>'.format(sys.argv[0]))
		sys.exit()

	e = ELF(sys.argv[1])
	main_addr = e.symbols['main']

	ip_analysis = InterproceduralAnalysis(e, main_addr, EspAnalysis, entry_state=((0,lattice.top), ()))
	for (addr, state), analysis in ip_analysis.analyses.items(): 
		print('Analysis for 0x{:x}:'.format(addr)) # add support for call site logging
		analysis.show()
		print('')
