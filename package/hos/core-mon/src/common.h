#ifndef COMMON_H
#define COMMON_H

#include "utils.h"

#define MAX_LINE_SIZE                 512
#define MAX_NAME_LEN                  256

void record_reboot_reason(const char *reason);
void collect_sys_info(void);
int check_cmd_response(const char *cmd, char *ret, u32 ret_size);

#endif // COMMON_H