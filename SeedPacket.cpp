//
// Created by evshiron on 11/2/15.
//

#include <iostream>

#include "SeedPacket.h"

using namespace std;

SeedPacket::SeedPacket() {

}

SeedPacket::SeedPacket(const u_char* data) {

    cout << "Size of data: " << sizeof(SeedPacket) << endl;

    memcpy(this, data, sizeof(SeedPacket));

    ProtocolType = ntohs(ProtocolType);

    Flags = ntohl(Flags);

    SessionId = ntohl(SessionId);

}

uint8_t SeedPacket::GetType() {

    return (Flags >> 24);

}

bool SeedPacket::IsBeginning() {

    return (Flags >> 23) & 0x1;

}

bool SeedPacket::IsEnding() {

    return (Flags >> 22) & 0x1;

}

int SeedPacket::GetPartId() {

    return Flags << 10 >> 10;

}

void SeedPacket::SetDestinationMac(uint8_t a, uint8_t b, uint8_t c, uint8_t d, uint8_t e, uint8_t f) {

    DestinationMac[0] = a;
    DestinationMac[1] = b;
    DestinationMac[2] = c;
    DestinationMac[3] = d;
    DestinationMac[4] = e;
    DestinationMac[5] = f;

}

void SeedPacket::SetSourceMac(uint8_t a, uint8_t b, uint8_t c, uint8_t d, uint8_t e, uint8_t f) {

    SourceMac[0] = a;
    SourceMac[1] = b;
    SourceMac[2] = c;
    SourceMac[3] = d;
    SourceMac[4] = e;
    SourceMac[5] = f;

}

void SeedPacket::SetType(int8_t type) {

    ((int8_t*) &Flags)[3] = type;

}

void SeedPacket::SetBeginning(bool isBeginning) {

    if(isBeginning) Flags |= 1 << 23;
    else Flags &= ~(1 << 23);

}

void SeedPacket::SetEnding(bool isEnding) {

    if(isEnding) Flags |= 1 << 22;
    else Flags &= ~(1 << 22);

}

void SeedPacket::SetPartId(int32_t partId) {

    int32_t flags = Flags >> 22 << 22;

    flags += partId << 10 >> 10;

    Flags = flags;

}

void SeedPacket::Cook() {

    ProtocolType = htons(ProtocolType);

    Flags = htonl(Flags);

    SessionId = htonl(SessionId);

}
