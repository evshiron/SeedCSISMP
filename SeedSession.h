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
#include "SeedSessionIdentity.h"

using namespace std;

class SeedCommandCenter;

class SeedSession {

public:

    SeedCommandCenter* CC;

    uint8_t Type;

    SeedSessionIdentity Identity;

    time_t CreatedTime;

    map<uint32_t, SeedPacket*> Packets;

    SeedSession(SeedCommandCenter* cc, uint8_t sessionType, SeedSessionIdentity& identity);

    void Consume(SeedPacket* packet);

    ~SeedSession();

private:

    int mPartCount;
    bool mIsCompleted;
    bool mIsAborted;

    char* assemble();

};


#endif //SEEDCSISMP_SEEDSESSION_H
