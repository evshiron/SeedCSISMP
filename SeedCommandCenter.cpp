//
// Created by evshiron on 11/3/15.
//

#include <time.h>
#include <string>

#include <vector>
#include <iostream>
#include <fstream>

#include "SeedCommandCenter.h"
#include "SeedPacket.h"

#define FILE_STUINFO "../StuInfo.txt"

#define PACKET_TYPE_ADD 1
#define PACKET_TYPE_DEL 2
#define PACKET_TYPE_ACK 3
#define PACKET_TYPE_RJT 4
#define PACKET_TYPE_SYNC 5

#define TLV_TYPE_NO 1
#define TLV_TYPE_NAME 2
#define TLV_TYPE_FACULTY 3

#define LENGTH_FACULTY 33
#define LENGTH_NO 14
#define LENGTH_NAME 24

#define FATAL(x) { cerr << x << endl; exit(1); }

SeedCommandCenter::SeedCommandCenter(const char* dev, SeedConfig& config) {

    mErrbuf = new char[PCAP_ERRBUF_SIZE];

    Handle = pcap_create(dev, mErrbuf);

    if(!Handle) FATAL("ERROR_PCAP_CREATE_FAILED");

}

void SeedCommandCenter::OutputSInfo() {

    map<string, SeedSInfo*> sInfo;

    for(auto it = RemoteSInfo.begin(); it != RemoteSInfo.end(); it++) {

        sInfo[(*it).first] = (*it).second;

    }

    for(auto it = LocalSInfo.begin(); it != LocalSInfo.end(); it++) {

        sInfo[(*it).first] = (*it).second;

    }

    vector<pair<string, SeedSInfo*>> ssInfo;

    for(auto it = sInfo.begin(); it != sInfo.end(); it++) {

        ssInfo.push_back(*it);

    }

    // TODO: Check if this works as expected.
    sort(ssInfo.begin(), ssInfo.end(), [&](pair<string, SeedSInfo*> a, pair<string, SeedSInfo*> b) -> bool {

        bool result = false;

        int facultyResult = strcmp(a.second->Faculty.c_str(), b.second->Faculty.c_str());

        if(facultyResult > 0) {

            result = true;

        }
        else if(facultyResult < 0) {

            result = false;

        }
        else {

            int noResult = strcmp(a.second->No.c_str(), b.second->No.c_str());

            if(noResult > 0) {

                result = true;

            }
            else if(noResult < 0) {

                result = false;

            }
            else {

                int nameResult = strcmp(a.second->Name.c_str(), b.second->Name.c_str());

                if(nameResult > 0) {

                    result = true;

                }
                else if(nameResult < 0) {

                    result = false;

                }
                else {

                    FATAL("ERROR_COMPARE_UNEXPECTED");

                }

            }

        }

        return result;

    });

    ofstream ofs(FILE_STUINFO, ios::app);

    time_t rawNow = time(0);
    char strNow[9];
    strftime(strNow, 9, "%X", localtime(&rawNow));

    ofs << "Time : " << strNow << endl;
    ofs << "Faculty" << string(LENGTH_FACULTY - 7 + 3, ' ');
    ofs << "Student ID" << string(LENGTH_NO - 10 + 3, ' ');
    ofs << "Name" << string(LENGTH_NAME - 4 + 3, ' ') << endl;
    ofs << string(80, '-') << endl;

    for(auto it = ssInfo.begin(); it != ssInfo.end(); it++) {

        string no((*it).second->No);
        string name((*it).second->Name);
        string faculty((*it).second->Faculty);

        for(int i = 0; i < faculty.length(); i++) {

            if(i != 0 && i % LENGTH_FACULTY == 0) ofs << endl;
            ofs << faculty[i];

        }
        ofs << string(LENGTH_FACULTY - faculty.length() % LENGTH_FACULTY + 3, ' ');

        ofs << no << string(LENGTH_NO - no.length() % LENGTH_NO + 3, ' ');
        ofs << name << string(LENGTH_NAME - name.length() % LENGTH_NAME + 3, ' ') << endl;

    }

    ofs << string(80, '-') << endl << endl;

    ofs.flush();
    ofs.close();

}

void SeedCommandCenter::Start() {

    cout << "Start." << endl;

    mIsStopped = false;

    pcap_set_buffer_size(Handle, BUFSIZ);
    pcap_set_promisc(Handle, true);
    //pcap_set_rfmon(Handle, true);

    //pcap_setnonblock(Handle, true, mErrbuf);

    pcap_set_timeout(Handle, 1);

    pcap_activate(Handle);

    // FIXME:
    mListener = new thread([&]() {

        listen();

    });

}

void SeedCommandCenter::listen() {

    bpf_program filter;

    pcap_compile(Handle, &filter, R"(ether proto 0x1122)", true, PCAP_NETMASK_UNKNOWN);

    pcap_setfilter(Handle, &filter);

    pcap_pkthdr* header;
    const u_char* data;

    SeedPacket* packet;

    while(!mIsStopped) {

        //cout << "Loop." << endl;

        switch(pcap_next_ex(Handle, &header, &data)) {

            case 1:

                cout << "Pcap captured." << endl;

                packet = new SeedPacket(data);

                dispatchPacket(packet);

                break;

            case -1:

                cerr << pcap_geterr(Handle) << endl;
                pcap_perror(Handle, mErrbuf);
                cerr << mErrbuf << endl;

                FATAL("ERROR_PCAP_CAPTURE_FAILED");

                break;

            case 0:

                //cout << "Pcap capture timeout." << endl;
                break;

        }

    }

    pcap_close(Handle);

}

void SeedCommandCenter::Collect(SeedSession* session, char* tlvs) {

    string no;
    string name;
    string faculty;

    switch(session->Type) {
        case PACKET_TYPE_ADD:

            cout << "Adding: " << endl;

            for(int i = 0; i < 128 * 1024; i++) {

                if(tlvs[i] == 0 && tlvs[i+1] == 0 && tlvs[i+2] == 0) {

                    break;

                }

                switch(tlvs[i]) {
                    case TLV_TYPE_NO:

                        no = string(&tlvs[i+2]);
                        cout << "No (" << (int) tlvs[i+1] <<  "): " << &tlvs[i+2] << endl;
                        i += 1 + tlvs[i+1];

                        break;

                    case TLV_TYPE_NAME:

                        name = string(&tlvs[i+2]);
                        cout << "Name (" << (int) tlvs[i+1] <<  "): " << &tlvs[i+2] << endl;
                        i += 1 + tlvs[i+1];

                        break;

                    case TLV_TYPE_FACULTY:

                        faculty = string(&tlvs[i+2]);
                        cout << "Faculty (" << (int) tlvs[i+1] <<  "): " << &tlvs[i+2] << endl;
                        i += 1 + tlvs[i+1];

                        LocalSInfo[no] = new SeedSInfo(no, name, faculty);

                        break;

                    case 0:
                    default:

                        FATAL("ERROR_COLLECT_UNEXPECTED");

                }

            }

            cout << "Added." << endl;

            OutputSInfo();

            break;
        case PACKET_TYPE_DEL:

            cout << "Deleting: " << endl;

            for(int i = 0; i < 128 * 1024; i++) {

                if(tlvs[i] == 0 && tlvs[i+1] == 0 && tlvs[i+2] == 0) {

                    break;

                }

                switch(tlvs[i]) {
                    case TLV_TYPE_NO:

                        cout << "No (" << (int) tlvs[i+1] <<  "): " << &tlvs[i+2] << endl;
                        i += 1 + tlvs[i+1];

                        break;

                    case 0:
                    default:

                        FATAL("ERROR_COLLECT_UNEXPECTED");

                }

            }

            break;
        case PACKET_TYPE_ACK:
            break;
        case PACKET_TYPE_RJT:
            break;
        case PACKET_TYPE_SYNC:
            break;
        default:
            cout << "WARNING_TYPE_UNKNOWN";
            break;
    }

}

void SeedCommandCenter::Stop() {

    mIsStopped = true;

    mListener->join();

}

void SeedCommandCenter::dispatchPacket(SeedPacket* packet) {

    if(Sessions.count(packet->SessionId) == 0) {

        Sessions[packet->SessionId] = new SeedSession(this, packet->GetType(), packet->SessionId);

    }

    SeedSession* session = Sessions[packet->SessionId];

    session->Consume(packet);

}
