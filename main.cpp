#include <iostream>
#include <sys/socket.h>
#include <pcap/pcap.h>

#include "SeedPacket.h"

using namespace std;

int main() {

    cout << "Hello, World!" << endl;

    char errbuf[PCAP_ERRBUF_SIZE];

    //pcap_findalldevs().
    //pcap_freealldevs().
    char* dev = pcap_lookupdev(errbuf);

    if(!dev) {
        cout << "Default device not found." << endl;
        cout << errbuf << endl;
    }

    // FIXME: Force set interface name here.
    // To be noticed, packets sent from non-working interfaces (Like "en1") will not be caught by WireShark.
    dev = "en0";
    cout << "Device: " << dev << endl;

    pcap_t* handle = pcap_create(dev, errbuf);

    if(!handle) {
        cout << "Device open failed." << endl;
        cout << errbuf << endl;
    }

    pcap_set_buffer_size(handle, BUFSIZ);
    //pcap_set_promisc(handle, 1);
    //pcap_set_rfmon(handle, 1);

    pcap_activate(handle);

    SeedPacket packet;

    packet.SetDestinationMac(0x12, 0x34, 0x56, 0x78, 0x90, 0xab);
    // Use of a fake MAC address is acceptable in Mac OS X.
    packet.SetSourceMac(0x12, 0x34, 0x56, 0x78, 0x90, 0xab);

    cout << sizeof(SeedPacket) << endl;
    cout << (long) &packet << endl;
    cout << (long) packet.destinationMac << endl;
    cout << (long) packet.sourceMac << endl;

    cout << (int) packet.GetType() << endl;
    cout << packet.IsBeginning() << endl;
    cout << packet.IsEnding() << endl;
    cout << packet.GetPartId() << endl;

    cout << pcap_inject(handle, &packet, sizeof(packet)) << endl;

    pcap_close(handle);

    return 0;

}


