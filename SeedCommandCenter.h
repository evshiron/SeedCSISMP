//
// Created by evshiron on 11/3/15.
//

#ifndef SEEDCSISMP_SEEDCOMMANDCENTER_H
#define SEEDCSISMP_SEEDCOMMANDCENTER_H

#include <thread>

#include <pcap/pcap.h>

#include "SeedConfig.h"

class SeedCommandCenter {

public:

    pcap_t* Handle;

    SeedCommandCenter(const char* dev, SeedConfig& config);

    void Start();
    void Stop();

private:

    char* mErrbuf;

    bool mIsStopped;

    thread* mListener;

    void listen();

};


#endif //SEEDCSISMP_SEEDCOMMANDCENTER_H
