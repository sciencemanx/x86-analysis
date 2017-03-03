int sub_one(int n) {
	return n - 1;
}

int neg(int n) {
	return -n;
}

int main() {
	int i, j, x, y;
	int a[10] = {};

	j = 0;
	for (i = 0; i < 10; i++) {
		if (i % 2 != 0) j++;
		else j--;
		a[sub_one(i)] = j; // off by one 
	}

	x = neg(5);
	y = a[x];
}
