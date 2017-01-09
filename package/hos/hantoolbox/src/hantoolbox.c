#include <stdio.h>
#include <string.h>
#include "str2hexascii.h"

void usage(const char *cmd)
{
	printf("Usage:\n");
	printf("%s <operation> [args...]\n", cmd);
	printf("operations:\n");
	printf("\tstr2hexascii\t<string>\n");

	printf("\n");
}

int main(int argc, char **argv) 
{
	if (argc < 2) {
		usage(argv[0]);
		return -1;
	}

	if (!strcmp(argv[1], "str2hexascii")) {
		str2hexascii(argv[2]);
	}
	else {
		usage(argv[0]);
		return -1;
	}

	return 0;
}
