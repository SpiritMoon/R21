/******************************************************************************
  File Name    : rogue_debug.c
  Author       : zhaoej
  Date         : 20160222
  Description  : debug
******************************************************************************/
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include "rogue_utils.h"
#define LEVEL_COUNT 5
char* debug[LEVEL_COUNT]= {"emerg","err","warning","info","debug"};

#define MODULE_ID 5
char * module[MODULE_ID] = {"driver","backgroud","cluster","web","rogueap"};
FILE *DUMP_FILE = NULL;

void rogue_debug(int module_id,int log_level,char *msg){
	int i,j;
	int level = log_level;
	int id = module_id;

	if(conf.debug){
		dump_file_open("a+");
		if(NULL!=msg){
			for(i=0;i<MODULE_ID;i++){
				for(j=0;j<LEVEL_COUNT;j++){
					if(i==id && j==level){
						fprintf(DUMP_FILE,"[MODULE:%s][DBG_LVL:%s]\t[MSG:%s]\n",module[i],debug[j],msg);
					}
				}
			}
		}
		dump_file_close();
	}
}

void dump_file_open(char *mode)
{
	DUMP_FILE = fopen(conf.dump_file, mode);
}

void dump_file_close(void)
{
	if (DUMP_FILE) {
		fclose(DUMP_FILE);
		DUMP_FILE = NULL;
	}
}

void buf_dump(unsigned char *buf, int len, struct sockaddr_un *addr,int sign)
{
	int i;
	if(buf_debug){
		printf("buf_dump start....\n");
		dump_file_open("a+");
		fprintf(DUMP_FILE, "\n");
		if (sign){
			fprintf(DUMP_FILE, "****************** Request ****************\n");
			fprintf(DUMP_FILE, "Peer addr:%s,   Msg Len:%d\n", addr->sun_path,len);
		} else {
			fprintf(DUMP_FILE, "****************** Response ****************\n");
			fprintf(DUMP_FILE, "Peer addr:%s,   Msg Len:%d\n",addr->sun_path,len);
		}
		for (i = 0; i < len; i++){
			if (i && (i % 2) == 0)
				fprintf(DUMP_FILE, " ");
			if (i && (i % 16) == 0)
				fprintf(DUMP_FILE, "\n");
			fprintf(DUMP_FILE, "%02x", buf[i]);
		}
		fprintf(DUMP_FILE, "\n");
		dump_file_close();		
		printf("buf_dump stop....\n");
	}
}

void packet_dump(char *buf,int len){
	int i;
	unsigned char * pos = NULL;
	pos = (unsigned char *)buf;
	if(packet_debug){
		dump_file_open("a+");
		fprintf(DUMP_FILE, "*************** Attack packet **************\n");
		for(i = 0; i < len; i++) {
			if (i && (i % 2) == 0)
				fprintf(DUMP_FILE, " ");
			if (i && (i % 16) == 0)
				fprintf(DUMP_FILE, "\n");
			fprintf(DUMP_FILE, "%02x", pos[i]);
		}
		fprintf(DUMP_FILE, "\n");
		dump_file_close();
	}
}

