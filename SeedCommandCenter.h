//
// Created by evshiron on 11/3/15.
//

#ifndef SEEDCSISMP_SEEDCOMMANDCENTER_H
#define SEEDCSISMP_SEEDCOMMANDCENTER_H

#include <thread>
#include <map>

#include <pcap/pcap.h>

#include "SeedConfig.h"
#include "SeedSession.h"
#include "SeedSInfo.h"

#define SIZE_DESTINATION_MAC 255

class SeedCommandCenter {

public:

    uint8_t LocalMac[6];
    uint8_t DestinationMacs[SIZE_DESTINATION_MAC][6];
    int DestinationMacCount = 0;

    pcap_t* Handle;

    map<uint32_t, SeedSession*> Sessions;

    map<string, SeedSInfo*> LocalSInfo;
    map<string, SeedSInfo*> RemoteSInfo;

    SeedCommandCenter(const char* dev, SeedConfig& config);

    void OutputSInfo();

    void Start();

    void AcceptPacket(SeedPacket *packet);
    void RejectPacket(SeedPacket *packet);

    void Collect(SeedSession* session, char* tlvs);

    void Stop();

private:

    char* mErrbuf;

    bool mIsStopped;

    thread* mListener;

    void convertMac(string source, uint8_t* out);
    int compareMac(uint8_t* a, uint8_t* b);
    void listen();
    void dispatchPacket(SeedPacket* packet);

};


#endif //SEEDCSISMP_SEEDCOMMANDCENTER_H
