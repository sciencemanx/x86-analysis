from collections import defaultdict
from CFG import op_str

class ForwardAnalysis(object):
	def __init__(self, cfg, entry_state=None):
		self.cfg = cfg
		self.before_states = defaultdict(lambda: self.empty_state())
		self.after_states = defaultdict(lambda: self.empty_state())
		self.entry_state = entry_state if entry_state is not None else self.empty_state()
		self.before_states[self.cfg.start] = self.entry_state
		self.analyze()

	def analyze(self):
		work_list = [self.cfg.start]

		while len(work_list) > 0:
			op = work_list.pop()
			in_state = self.before_states[op]
			out_state = self.flow_func(in_state, op)
			self.after_states[op] = out_state
			for succ_addr in op.succs:
				next_op = self.cfg[succ_addr]
				next_state = self.before_states[next_op]
				merged = self.merge(out_state, next_state)
				if merged != next_state:
					if next_op not in work_list:
						work_list.append(next_op)
					self.before_states[next_op] = merged

	def __repr__(self):
		return '{}(0x{:x})'.format(self.__class__.__name__, self.cfg.start_addr)

	def show(self):
		for op, state in sorted(self.before_states.items(), key=lambda x:x[0].address):
			self.show_state(op, state)

	def show_state(self, op, state):
		print('{}: {}'.format(op_str(op), state))

	def empty_state(self):
		raise NotImplementedError

	# takes in two analysis states and returns a new merged copy
	# you should /not/ mutate either input state
	def merge(self, s1, s2):
		raise NotImplementedError

	# returns the a new state for the flow function of the operand and state
	# you should /not/ mutate the input state
	def flow_func(self, state, op):
		raise NotImplementedError
