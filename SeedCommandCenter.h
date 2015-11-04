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

class SeedCommandCenter {

public:

    pcap_t* Handle;

    map<uint32_t, SeedSession*> Sessions;

    SeedCommandCenter(const char* dev, SeedConfig& config);

    void Start();

    void Collect(SeedSession* session, char* tlvs);

    void Stop();

private:

    char* mErrbuf;

    bool mIsStopped;

    thread* mListener;

    void listen();
    void dispatchPacket(SeedPacket* packet);

};


#endif //SEEDCSISMP_SEEDCOMMANDCENTER_H
