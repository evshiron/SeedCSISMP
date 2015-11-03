//
// Created by evshiron on 11/3/15.
//

#ifndef SEEDCSISMP_SEEDCONFIG_H
#define SEEDCSISMP_SEEDCONFIG_H

#include <string>
#include <list>

using namespace std;

class SeedConfig {

public:

    string LocalMac;
    list<string> DestinationMacs;

    SeedConfig(const char* path);

    string ToString();

private:

    void parseLocalMac(string& config);
    void parseDestinationMacs(string& config);

};


#endif //SEEDCSISMP_SEEDCONFIG_H
