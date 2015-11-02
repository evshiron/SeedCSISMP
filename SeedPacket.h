//
// Created by evshiron on 11/2/15.
//

#ifndef SEEDCSISMP_SEEDPACKET_H
#define SEEDCSISMP_SEEDPACKET_H

#include <iostream>
#include <pcap/pcap.h>

// Disable memory alignment.
#pragma pack(1)

class SeedPacket {

public:

    uint8_t destinationMac[6];
    uint8_t sourceMac[6];
    uint16_t protocolType = htons(0x1122);

    // 8-byte flags.
    uint32_t flags;
    uint32_t sessionId;

    uint8_t tlvs[1024];

    SeedPacket();

    uint8_t GetType();
    bool IsBeginning();
    bool IsEnding();
    int GetPartId();

    void SetDestinationMac(uint8_t a, uint8_t b, uint8_t c, uint8_t d, uint8_t e, uint8_t f);
    void SetSourceMac(uint8_t a, uint8_t b, uint8_t c, uint8_t d, uint8_t e, uint8_t f);

    // TODO: Implementation.
    void SetBeginning(bool isBeginning);
    void SetEnding(bool isEnding);

};


#endif //SEEDCSISMP_SEEDPACKET_H
