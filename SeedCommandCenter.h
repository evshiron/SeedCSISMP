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
#include "SeedSessionIdentity.h"

#define SIZE_DESTINATION_MAC 255

struct SeedSessionComparer
{
    bool operator()(const SeedSessionIdentity& a, const SeedSessionIdentity& b) const
    {
        if(memcmp((void*) a.Bytes, (void*) b.Bytes, 16) == 0) return false;
        return true;
    }
};

class SeedCommandCenter {

public:

    uint8_t LocalMac[6];
    uint8_t DestinationMacs[SIZE_DESTINATION_MAC][6];
    int DestinationMacCount = 0;

    pcap_t* Handle;

    time_t SyncTime;

    map<SeedSessionIdentity, SeedSession*, SeedSessionComparer> Sessions;

    map<string, SeedSInfo*> LocalSInfo;
    map<string, SeedSInfo*> RemoteSInfo;

    SeedCommandCenter(const char* dev, SeedConfig& config);

    void OutputSInfo();

    void Start();

    //void AcceptPacket(SeedPacket *packet);
    //void RejectPacket(SeedPacket *packet);
    void AcceptSession(SeedSession* session);
    void RejectSession(SeedSession* session, SeedPacket* packet, string reason);

    void Abort(SeedSession* session);
    void Collect(SeedSession* session, char* tlvs);

    void SendSInfo();

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
