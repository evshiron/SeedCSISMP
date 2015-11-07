#include <iostream>
#include <sys/socket.h>
#include <pcap/pcap.h>

#include "SeedConfig.h"
#include "SeedCommandCenter.h"

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
    //dev = "en0";
    cout << "Device: " << dev << endl;

    SeedConfig config;
    SeedCommandCenter cc(dev, config);
    cc.Start();

    return 0;

}


