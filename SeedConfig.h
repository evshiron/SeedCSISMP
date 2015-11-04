//
// Created by evshiron on 11/3/15.
//

#ifndef SEEDCSISMP_SEEDCONFIG_H
#define SEEDCSISMP_SEEDCONFIG_H

#include <string>
#include <list>

#define FILE_CONFIG "../Config.txt"
#define FILE_CFGINFO "../CfgInfo.txt"

using namespace std;

class SeedConfig {

public:

    string LocalMac;
    list<string> DestinationMacs;

    SeedConfig(const char* path);
    SeedConfig() : SeedConfig(FILE_CONFIG) {}

    string ToString();
    void Output();

private:

    void parseLocalMac(string& config);
    void parseDestinationMacs(string& config);

};


#endif //SEEDCSISMP_SEEDCONFIG_H
