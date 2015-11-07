//
// Created by evshiron on 11/7/15.
//

#ifndef SEEDCSISMP_SEEDSESSIONIDENTITY_H
#define SEEDCSISMP_SEEDSESSIONIDENTITY_H

#include <iostream>
#include <string.h>

class SeedSessionIdentity {

public:

    uint8_t Bytes[16];

    SeedSessionIdentity();
    SeedSessionIdentity(uint8_t* destinationMac, uint8_t* sourceMac, uint32_t sessionId);

    uint32_t GetSessionId();

};


#endif //SEEDCSISMP_SEEDSESSIONIDENTITY_H
