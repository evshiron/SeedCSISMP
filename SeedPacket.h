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

    uint8_t DestinationMac[6];
    uint8_t SourceMac[6];
    uint16_t ProtocolType = 0x1122;

    // 8-byte flags.
    uint32_t Flags;
    uint32_t SessionId;

    uint8_t Tlvs[1024];

    SeedPacket();
    SeedPacket(const u_char* data);

    uint8_t GetType();
    bool IsBeginning();
    bool IsEnding();
    uint32_t GetPartId();

    void SetDestinationMac(uint8_t a, uint8_t b, uint8_t c, uint8_t d, uint8_t e, uint8_t f);
    void SetSourceMac(uint8_t a, uint8_t b, uint8_t c, uint8_t d, uint8_t e, uint8_t f);

    void SetType(int8_t type);
    void SetBeginning(bool isBeginning);
    void SetEnding(bool isEnding);
    void SetPartId(uint32_t partId);

    void Cook();

    void Print();

};


#endif //SEEDCSISMP_SEEDPACKET_H
