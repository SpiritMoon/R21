#include <iostream>
#include <fstream>

#include <arpa/inet.h>
#include <cstring>
#include <cstdlib>

#include "firmware-hd.h"

FirmwareHeaderDump::FirmwareHeaderDump()
{
    memset(binName, 0, sizeof(binName));
    memset(root_node_buf, 0, sizeof(root_node_buf));
    memset(tmpBuf, 0, sizeof(tmpBuf));
}

nodeTypeE FirmwareHeaderDump::getRootNodeType(ifstream &inFile)
{
    if (inFile.good()) {
        memset(tmpBuf, 0, sizeof(tmpBuf));

        inFile.read(tmpBuf, 1);
        if (tmpBuf[0] == 0x01) {
            return TYPE_ROOT_HEAD;
        }
    }

    return TYPE_INVALID_MAX;
}

/**
 * return 0 for err
 */
uint32_t FirmwareHeaderDump::getRootNodeLength(ifstream &inFile)
{
    if (inFile.good()) {
        memset(tmpBuf, 0, sizeof(tmpBuf));

        inFile.read(tmpBuf, 4);

        uint32_t node_len = ntohl(*(uint32_t *)&tmpBuf[0]);
        if (node_len < 1024) {
            return node_len;
        }
    }

    return 0;
}

/**
 * TLV: Type(1B) + Length(4B) + Value
 */
int FirmwareHeaderDump::getRootNodeInfo(const char *fname)
{
    ifstream inFile;

    inFile.open(fname, ios::binary | ios::in);
    if (! inFile.is_open()) { // failed to open
        cout << "open failed" << endl;
        return -1;
    }

    // read root node type
    nodeTypeE root_node_type = getRootNodeType(inFile);
    if (root_node_type != TYPE_ROOT_HEAD) {
        inFile.close();
        cout << "get root node type err" << endl;
        return -2;
    }

    // read root node length
    uint32_t root_node_len = getRootNodeLength(inFile);
    if (root_node_len == 0) {
        inFile.close();
        cout << "get root node len err" << endl;
        return -3;
    }

    // read root node value for analysis
    if (inFile.good()) {
        inFile.read(root_node_buf, root_node_len);
    }

    inFile.close();

    return 0;
}

nodeTypeE FirmwareHeaderDump::getNormalNodeType(const char *buf, uint32_t offset)
{
    int type = buf[offset];

    if (type < TYPE_INVALID_MAX) {
        return (nodeTypeE)type;
    }

    return TYPE_INVALID_MAX;
}

/**
 * return 0 for err
 */
uint32_t FirmwareHeaderDump::getNormalNodeLength(const char *buf, uint32_t offset)
{
    uint32_t node_len = ntohl(*(uint32_t *)&buf[offset]);

    if (node_len < 1024) {
        return node_len;
    }

    return 0;
}

const char *FirmwareHeaderDump::getNormalNodeValue(const char *buf, uint32_t offset)
{
    return buf+offset;
}

void FirmwareHeaderDump::analysisBinHeader(const char *fname)
{
    if (getRootNodeInfo(fname) < 0) {
        exit(EXIT_FAILURE);
    }

    const int c_type_size = 1;
    const int c_len_size = 4;
    uint32_t offset = 0;

    // get md5 info
    nodeTypeE md5_node_type = getNormalNodeType(root_node_buf, offset);
    if (md5_node_type != TYPE_CNT_MD5) {
        cout << "not md5 node type" << endl;
        exit(EXIT_FAILURE);
    }
    offset += c_type_size;
    uint32_t md5_node_len = getNormalNodeLength(root_node_buf, offset);
    offset += c_len_size;
    const char* md5_node_val = getNormalNodeValue(root_node_buf, offset);
    cout << "md5:" << md5_node_val << endl;

    // get version info
    offset += md5_node_len;
    nodeTypeE ver_node_type = getNormalNodeType(root_node_buf, offset);
    if (ver_node_type != TYPE_CNT_VERSION) {
        cout << "not version node type" << endl;
        exit(EXIT_FAILURE);
    }
    offset += c_type_size;
    uint32_t ver_node_len = getNormalNodeLength(root_node_buf, offset);
    offset += c_len_size;
    const char * ver_node_val = getNormalNodeValue(root_node_buf, offset);
    cout << "version:" << ver_node_val << endl;

    // get device info
    offset += ver_node_len;
    nodeTypeE dev_node_type = getNormalNodeType(root_node_buf, offset);
    if (dev_node_type != TYPE_CNT_DEVINFO) {
        cout << "not device info not type" << endl;
        exit(EXIT_FAILURE);
    }
    offset += c_type_size;
    uint32_t dev_node_len = getNormalNodeLength(root_node_buf, offset);
    offset += c_len_size;
    const char * dev_node_val = getNormalNodeValue(root_node_buf, offset);
    cout << "devinfo:" << dev_node_val << endl;
}

int main(int argc, char *argv[])
{
    if (argc != 2) {
        cout << "Usage: " << argv[0] << " " << "firmware-name" << endl;
        return -1;
    }

    FirmwareHeaderDump fm_hd;
    fm_hd.analysisBinHeader(argv[1]);

    return 0;
}
