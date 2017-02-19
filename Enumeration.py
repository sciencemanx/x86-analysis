
class Enumeration:
	def __init__(self, names):  # or *names, with no .split()
		for number, name in enumerate(names.split()):
			setattr(self, name, Enumeration.EnumItem(name, number))

	class EnumItem:
		def __init__(self, name, n):
			self.name = name
			self.n = n
		def __eq__(self, other):
			if isinstance(self, type(other)):
				return self.n == other.n
			else:
				return False
		def __repr__(self):
			return self.name


