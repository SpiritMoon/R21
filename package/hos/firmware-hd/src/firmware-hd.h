#ifndef FIRMWAREHD_H
#define FIRMWAREHD_H

#include <fstream>
using namespace std;

#define NAME_SIZE 128
#define BUF_SIZE  1024

typedef enum {
    TYPE_ROOT_HEAD = 1,
    TYPE_CNT_MD5,
    TYPE_CNT_VERSION,
    TYPE_CNT_DEVINFO,

    TYPE_INVALID_MAX,
} nodeTypeE;

class FirmwareHeaderDump
{

public:
    FirmwareHeaderDump();
    void analysisBinHeader(const char *fname);

private:
    char binName[NAME_SIZE];
    char root_node_buf[BUF_SIZE];
    char tmpBuf[BUF_SIZE];

    nodeTypeE getRootNodeType(ifstream &inFile);
    uint32_t getRootNodeLength(ifstream &inFile);
    int getRootNodeInfo(const char *fname);

    nodeTypeE getNormalNodeType(const char *buf, uint32_t offset);
    uint32_t getNormalNodeLength(const char *buf, uint32_t offset);
    const char *getNormalNodeValue(const char *buf, uint32_t offset);
};


#endif // FIRMWAREHD_H
