from capstone import *
from capstone.x86 import *
from pwnlib.elf import ELF
import sys

MAX_INST_LEN = 15
NUM_REGS = 234

md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True

def op_str(op):
	return '\t0x{:x}: {} {}'.format(op.address, op.mnemonic, op.op_str)

class BasicBlock:
	def __init__(self, insn=None):
		self.in_blocks = []
		self.out_blocks = []
		self.insn = insn if insn else []

	def start(self):
		return self.insn[0]

	def end(self):
		return self.insn[-1]

	def __repr__(self):
		return 'BasicBlock({}, {}, {})'.format(self.insn, self.in_blocks, self.out_blocks)

def build_basic_blocks(opgraph):
	ops = [opgraph[addr] for addr in sorted(opgraph.keys())]

	splits = []
	for op in ops:
		if len(op.succs) >= 2 or op.id == X86_INS_JMP: #make this not suck
			splits += op.succs

	basic_blocks = {}
	block = BasicBlock()
	for op in ops:
		if op.address in splits:
			basic_blocks[block.start().address] = block
			block = BasicBlock()
		block.insn.append(op)
	basic_blocks[block.start().address] = block

	for start_addr, block in basic_blocks.items():
		succs = block.insn[-1].succs
		for s in succs:
			if s not in basic_blocks:
				continue
			basic_blocks[s].in_blocks.append(block)
			block.out_blocks.append(basic_blocks[s])

	return basic_blocks

def get_jmp_target(op):
	target = op.operands[0]
	if target.type == X86_OP_IMM:
		return target.imm

def succ(op):
	addrs = []
	if op.id not in [X86_INS_RET, X86_INS_RETF, X86_INS_RETFQ, X86_INS_JMP]:
		addrs.append(op.address + op.size)
	if X86_GRP_JUMP in op.groups:
		addrs.append(get_jmp_target(op))
	return addrs

def construct_cfg(elf, start_addr):
	work_queue = [start_addr]
	cfg = {}

	while len(work_queue) > 0:
		addr = work_queue.pop()
		if addr in cfg:
			continue
		code = elf.read(addr, MAX_INST_LEN)
		op = next(md.disasm(code, addr))
		op.succs = succ(op)
		cfg[addr] = op
		work_queue += op.succs

	blocks = build_basic_blocks(cfg)
	return blocks[start_addr]

def print_cfg(cfg):
	visited = set()
	work_list = [cfg]
	while len(work_list) > 0:
		block = work_list.pop()
		visited.add(block)
		
		print('printing block {:x}'.format(block.start().address))
		for i in block.insn:
			print(op_str(i))

		for out_block in block.out_blocks:
			if out_block not in visited:
				work_list.append(out_block)

if __name__ == '__main__':
	if len(sys.argv) != 2:
		print('Usage: {} <file>'.format(sys.argv[0]))
		sys.exit()

	e = ELF(sys.argv[1])
	main_addr = e.symbols['main']

	cfg = construct_cfg(e, main_addr)
	print_cfg(cfg)
