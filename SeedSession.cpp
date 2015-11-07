//
// Created by evshiron on 11/4/15.
//

#include <string.h>

#include "SeedSession.h"
#include "SeedCommandCenter.h"

#define SIZE_ASSEMBLY 128 * 1024

#define FATAL(x) { cerr << x << endl; exit(1); }

SeedSession::SeedSession(SeedCommandCenter* cc, uint8_t type, uint32_t sessionId) {

    CC = cc;

    Type = type;

    SessionId = sessionId;

    CreatedTime = time(0);

    mPartCount = 0;
    mIsCompleted = false;
    mIsAborted = false;

}

void SeedSession::Consume(SeedPacket* packet) {

    if(packet->SessionId == SessionId) {

        cout << "Packet collected by session " << SessionId << "." << endl;

        if(packet->IsBeginning() && packet->IsEnding()) {

            Packets[packet->GetPartId()] = packet;

            mPartCount = 1;
            mIsCompleted = true;
            mIsAborted = false;

        }
        else if(packet->IsEnding()) {

            Packets[packet->GetPartId()] = packet;

            mPartCount = packet->GetPartId() + 1;

        }
        else {

            // Check if the PartId is beyond PartCount.
            if(mPartCount > 0 && packet->GetPartId() >= mPartCount) {

                //CC->RejectPacket(packet);
                CC->RejectSession(this, packet, "REJECT_PACKET_PART_ID_UNEXPECTED");
                delete packet;

            }
            else {

                Packets[packet->GetPartId()] = packet;

            }

        }

    }
    else {

        packet->Print();
        FATAL("ERROR_SESSION_UNEXPECTED");

    }

    if(mPartCount > 0) {

        bool isCompleted = true;

        for(uint32_t i = 0; i < mPartCount; i++) {

            if(Packets.count(i) == 0) {

                isCompleted = false;
                break;

            }

        }

        mIsCompleted = isCompleted;

    }

    if(mIsAborted) {

        cout << "Session " << SessionId << " aborted." << endl;

        CC->Abort(this);

    }

    if(mIsCompleted) {

        cout << "Session " << SessionId << " completed." << endl;

        char* tlvs = assemble();

        if(tlvs != 0) CC->Collect(this, tlvs);

    }

}

char* SeedSession::assemble() {

    char* assembly = new char[SIZE_ASSEMBLY];
    int offset = 0;

    for(uint32_t i = 0; i < mPartCount; i++) {

        SeedPacket* packet = Packets[i];

        if(packet->Tlvs[0] == 0 && packet->Tlvs[1] == 0) {

            CC->RejectSession(this, packet, "REJECT_TLV_UNEXPECTED");
            delete[] assembly;
            return 0;

        }

        for(int j = 2; j < 1023; j++) {

            // If the current is the ending type.
            if(packet->Tlvs[j-1] == 0 && packet->Tlvs[j] == 0 && packet->Tlvs[j+1] == 0) {

                memcpy(assembly + offset, &packet->Tlvs, j);
                offset += j;
                goto NEXT_PACKET;

            }

        }

        CC->RejectSession(this, packet, "REJECT_TLVS_NO_ENDING");
        delete[] assembly;
        return 0;

        NEXT_PACKET: cout;

    }

    memset(assembly + offset, '\0', 2);
    offset += 2;

    cout << "Assembly size: " << offset - 1 << endl;

    return assembly;

}

SeedSession::~SeedSession() {

    for(auto it = Packets.begin(); it != Packets.end(); it++) {

        SeedPacket* packet = (*it).second;
        delete packet;

    }

}
