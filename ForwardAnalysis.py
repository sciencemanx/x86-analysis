from collections import defaultdict

class ForwardAnalysis:
	def __init__(self, cfg, entry_state=None):
		self.cfg = cfg
		self.flow_func = flow_func
		self.before_states = defaultdict(lambda: self.empty_state())
		self.after_states = defaultdict(lambda: self.empty_state())
		self.entry_state = entry_state if entry_state else self.empty_state()
		self.before_states[self.cfg.start] = self.entry_state

	def analyze(self):
		work_list = [self.cfg.start]

		while len(work_list) > 0:
			op = work_list.pop()
			in_state = self.before_states[op]
			out_state = self.flow_func(in_state, op)
			self.after_states[op] = out_state
			for succ_addr in op.succs:
				next_op = self.cfg[succ_addr]
				next_state = self.in_state[next_op]
				self.in_state[next_op] = self.merge(out_state, next_state)


	# takes in two analysis states and returns a new merged copy
	# you should /not/ mutate either input state
	def merge(self, s1, s2):
		raise NotImplementedError

	# returns the a new state for the flow function of the operand and state
	# you should /not/ mutate the input state
	def flow_func(self, state, op):
		raise NotImplementedError

	def empty_state(self):
		raise NotImplementedError
