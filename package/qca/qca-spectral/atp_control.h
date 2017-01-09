#ifndef __ATP_CONTROL_H__
#define __ATP_CONTROL_H__
#define WIFI0_MAX_TXPOWER 20
#define WIFI1_MAX_TXPOWER 23

typedef struct {
    int txpower;
    int rssi;
}txpower_estimate;

typedef struct {
    int meter;
    int best_txpower;
    txpower_estimate txpower_and_rssi[8];
}distance_estimate;

void atp_control_timer();
#endif
