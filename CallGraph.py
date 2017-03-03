from CFG import CFG
from pwnlib.elf import ELF
from capstone.x86 import *

class CallGraph(object):
	def __init__(self, elf, start_addr):
		self.elf = elf
		self.start_addr = start_addr
		self.cfgs = {} # maps func addr to cfg
		self.calls = {} # maps call site to 'call dest'
		self.construct()

	def construct(self):
		def extract_calls(cfg): # get all calls from cfg
			calls = {}
			visited = set()
			work_list = [cfg.start]
			while len(work_list) > 0:
				op = work_list.pop()
				visited.add(op)
				# indirect calls (call %rcx, etc) not currently supported
				if op.id == X86_INS_CALL and op.operands[0].type == X86_OP_IMM:
					calls[op.address] = op.operands[0].imm
				for succ in op.succs:
					succ_op = cfg[succ]
					if succ_op not in visited:
						work_list.append(succ_op)
			return calls

		worklist = [self.start_addr]
		while len(worklist) > 0:
			func_addr = worklist.pop()
			func_cfg = CFG(self.elf, func_addr)
			func_calls = extract_calls(func_cfg)

			self.cfgs[func_addr] = func_cfg
			self.calls.update(func_calls)
			worklist.extend(set(func_calls.values()) - set(self.cfgs))

if __name__ == '__main__':
	import sys

	if len(sys.argv) != 2:
		print('Usage: {} <file>'.format(sys.argv[0]))
		sys.exit()

	e = ELF(sys.argv[1])
	main_addr = e.symbols['main']

	call_graph = CallGraph(e, main_addr)
	print(map(hex, call_graph.cfgs.keys()))
	print(call_graph.calls)
