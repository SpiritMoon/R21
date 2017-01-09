#include <arpa/inet.h>

#define TYPE_ROOT_HEAD                0x01
#define TYPE_CNT_MD5                  0x02
#define TYPE_CNT_VERSION              0x03
#define TYPE_CNT_DEVINFO              0x04

#pragma pack(1)
typedef struct tlv_node {
    unsigned char type;
    uint32_t len;
    char *p_buf;

} tlv_node_st, *p_tlv_node_st;
#pragma pack()

#define NODE_TYPE_SIZE                (sizeof(unsigned char))
#define NODE_LEN_SIZE                 (sizeof(uint32_t))

