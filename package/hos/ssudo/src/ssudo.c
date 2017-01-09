/*******************************************************************************
  Copyright (c) 2012-2016, HAN Networks. All rights reserved.
 *******************************************************************************/


#include <unistd.h>
#include <sys/types.h>
#include <string.h>
#include <sys/stat.h>
#include <libgen.h>
#include <stdio.h>
#include <stdlib.h>

static struct {
	char *file;
	char *argv0;
}p[]= {
	{"/sbin/reboot", "reboot"},
	{"/sbin/firstboot", "firstboot"},
	{"/bin/ping", "ping"},
	{"/usr/sbin/userm_cli", "userm_cli"},
	{"/sbin/ifconfig", "ifconfig"},
	{"/usr/bin/traceroute", "traceroute"},
};

/* 最基本的简单检查, 无保证, 本程序属于危险程序 */
static int file_is_safe(int i)
{
	struct stat buf;
	stat(p[i].file, &buf);
	if(buf.st_uid != 0 || buf.st_gid != 0
			|| (S_IWOTH & buf.st_mode) || (S_IWGRP & buf.st_mode))
		return 0;
	return 1;
}

int main(int argc, char **argv)
{
	int i;

	if(argc < 2)
	{
		fprintf(stderr, "Usage: %s command\n"
				"   eg: %s reboot\n", argv[0], argv[0]);
		exit(1);
	}

	for(i = 0; i < sizeof(p)/sizeof(p[0]); i++)
	{
		if(strcmp(p[i].argv0, argv[1]) == 0
				|| strcmp(p[i].file, argv[1]) == 0)
			break;
	}

	if(i == sizeof(p)/sizeof(p[0]))
	{
		fprintf(stderr, "%s permission denied\n", argv[1]);
		exit(1);
	}

	if(!file_is_safe(i))
	{
		fprintf(stderr, "%s permission unexpected\n", argv[0]);
		exit(1);
	}

	if(setuid(0) != 0)
	{
		fprintf(stderr, "%s permission denied\n", argv[0]);
		exit(1);
	}
	setenv("USER", "root", 1);
	setenv("LOGNAME", "root", 1);

	execvp(p[i].file, &argv[1]);
	return 0;
}
