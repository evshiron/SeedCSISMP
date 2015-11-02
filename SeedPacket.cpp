//
// Created by evshiron on 11/2/15.
//

#include "SeedPacket.h"

SeedPacket::SeedPacket() {

}

uint8_t SeedPacket::GetType() {

    return (uint8_t) (flags >> 24);

}

bool SeedPacket::IsBeginning() {

    return (flags >> 23) & 0x1;

}

bool SeedPacket::IsEnding() {

    return (flags >> 22) & 0x1;

}

int SeedPacket::GetPartId() {

    return flags << 10 >> 10;

}

void SeedPacket::SetDestinationMac(uint8_t a, uint8_t b, uint8_t c, uint8_t d, uint8_t e, uint8_t f) {

    destinationMac[0] = a;
    destinationMac[1] = b;
    destinationMac[2] = c;
    destinationMac[3] = d;
    destinationMac[4] = e;
    destinationMac[5] = f;

}

void SeedPacket::SetSourceMac(uint8_t a, uint8_t b, uint8_t c, uint8_t d, uint8_t e, uint8_t f) {

    sourceMac[0] = a;
    sourceMac[1] = b;
    sourceMac[2] = c;
    sourceMac[3] = d;
    sourceMac[4] = e;
    sourceMac[5] = f;

}
