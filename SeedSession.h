//
// Created by evshiron on 11/4/15.
//

#ifndef SEEDCSISMP_SEEDSESSION_H
#define SEEDCSISMP_SEEDSESSION_H

#include <iostream>
#include <list>
#include <thread>
#include <map>

#include "SeedPacket.h"

using namespace std;

class SeedCommandCenter;

class SeedSession {

public:

    SeedCommandCenter* CC;

    uint32_t SessionId;

    map<uint32_t, SeedPacket*> Packets;

    SeedSession(SeedCommandCenter* cc, uint32_t sessionId);

    void Consume(SeedPacket* packet);

    ~SeedSession();

private:

    int mPartCount;
    bool mIsCompleted;
    bool mIsAborted;

    thread* mUpdater;

    void update();

    char* assemble();

};


#endif //SEEDCSISMP_SEEDSESSION_H
