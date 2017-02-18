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
		