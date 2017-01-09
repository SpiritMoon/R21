#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "str2hexascii.h"

static void usage(void)
{
	printf("usage:\n");
	printf("str2hexascii <string>\n\n");
}

static int _str_2_hex_ascii(const char *str, char *ascii_buf, int bufsize)
{
	int i = 0; 
	int ch_cnt = 0; 

	memset(ascii_buf, 0, bufsize);
	while ((str[i] != '\0') && (i < bufsize)) {
		sprintf((ascii_buf + ch_cnt), "%2x", (str[i] & 0xff));
		i++;
		ch_cnt += 2;
	}

	return strlen(ascii_buf);
}

int str_2_hex_ascii(const char *str, char *ascii_buf, int bufsize)
{
	return _str_2_hex_ascii(str, ascii_buf, bufsize);
}

int str2hexascii(const char * str)
{
	char *buf;
	int size;
	int count;

	if (str == NULL) {
		usage();
		return -1;
	}

	size = strlen(str) * 2 + 4;
	buf = malloc(size);
	memset(buf, 0, size);

	count = _str_2_hex_ascii(str, buf, size);
	puts(buf);

	free(buf);

	return size;
}
