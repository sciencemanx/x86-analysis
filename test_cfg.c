int main() {
	int i, j;

	j = 0;
	for (i = 0; i < 10; i++) {
		if (i % 3 != 0) j++;
		else j--;
	}
}