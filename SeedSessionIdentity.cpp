//
// Created by evshiron on 11/7/15.
//

#include "SeedSessionIdentity.h"

SeedSessionIdentity::SeedSessionIdentity() {

    memset(Bytes, 0xff, 16);

}

SeedSessionIdentity::SeedSessionIdentity(uint8_t* destinationMac, uint8_t* sourceMac, uint32_t sessionId) {

    memcpy(&Bytes[0], destinationMac, 6);
    memcpy(&Bytes[6], sourceMac, 6);
    memcpy(&Bytes[12], &sessionId, 4);

}

uint32_t SeedSessionIdentity::GetSessionId() {

    uint32_t sessionId = *((uint32_t*) &Bytes[12]);

    return sessionId;

}
