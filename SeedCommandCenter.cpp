//
// Created by evshiron on 11/3/15.
//

#include <iostream>
#include <functional>

#include "SeedCommandCenter.h"
#include "SeedPacket.h"

#define FATAL(x) { cerr << x << endl; exit(1); }

SeedCommandCenter::SeedCommandCenter(const char* dev, SeedConfig& config) {

    mErrbuf = new char[PCAP_ERRBUF_SIZE];

    Handle = pcap_create(dev, mErrbuf);

    if(!Handle) FATAL("ERROR_PCAP_CREATE_FAILED");

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

    SeedPacket packetReceived;

    while(!mIsStopped) {

        //cout << "Loop." << endl;

        switch(pcap_next_ex(Handle, &header, &data)) {

            case 1:

                cout << "Pcap captured." << endl;

                packetReceived = SeedPacket(data);

                cout << (int) packetReceived.GetType() << endl;
                cout << packetReceived.IsBeginning() << endl;
                cout << packetReceived.IsEnding() << endl;
                cout << packetReceived.GetPartId() << endl;
                break;

            case -1:

                cout << "Pcap capture failed." << endl;
                cout << pcap_geterr(Handle) << endl;
                pcap_perror(Handle, mErrbuf);
                cout << mErrbuf << endl;
                break;

            case 0:

                //cout << "Pcap capture timeout." << endl;
                break;

        }

    }

    pcap_close(Handle);

}

void SeedCommandCenter::Stop() {

    mIsStopped = true;

}
