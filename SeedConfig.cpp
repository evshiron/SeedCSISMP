//
// Created by evshiron on 11/3/15.
//

#include "SeedConfig.h"

#include <iostream>
#include <regex>
#include <fstream>

#define FATAL(x) { cerr << x << endl; exit(1); }

SeedConfig::SeedConfig(const char* path) {

    FILE* file = fopen(path, "rb");

    if(!file) {

        FATAL("ERROR_CONFIG_NOT_FOUND");

    }

    fseek(file, 0L, SEEK_END);
    size_t size = ftell(file);
    rewind(file);

    char bytes[size];

    size_t s = fread(bytes, 1, size, file);
    if (size != s) FATAL("ERROR_SIZE_NOT_MATCH");

    string config(bytes);

    //cout << config << endl;

    parseLocalMac(config);
    parseDestinationMacs(config);

    fclose(file);

}

string SeedConfig::ToString() {

    string out;
    out.append("local mac : ").append(LocalMac).append("\n");
    out.append("destination mac : ");

    for(auto it = DestinationMacs.begin(); it != DestinationMacs.end(); it++) {

        out.append(*it).append("\n");

    }

    return out;

}

void SeedConfig::Output() {

    ofstream ofs(FILE_CFGINFO, ios::trunc);
    ofs << ToString() << endl;
    ofs.flush();
    ofs.close();

}

void SeedConfig::parseLocalMac(string& config) {

    regex regexLocalMac("local mac\\s*:\\s*([a-fA-F0-9-]+)");

    smatch match;

    regex_search(config, match, regexLocalMac);

    //cout << match[0] << endl;
    //cout << match[1] << endl;

    string localMac(match[1]);
    for(auto& c : localMac) c = toupper(c);

    LocalMac = localMac;

}

void SeedConfig::parseDestinationMacs(string& config) {

    regex regexDestinationMacs("destination mac\\s*:\\s*([a-fA-F0-9-]+(:?\\s+[a-fA-F0-9-]+)*)");
    smatch match;
    regex_search(config, match, regexDestinationMacs);

    //cout << match[0] << endl;
    //cout << match[1] << endl;

    string macs(match[1]);

    regex regexMacDelimiter("\\s+");
    sregex_token_iterator begin(macs.begin(), macs.end(), regexMacDelimiter, -1);
    sregex_token_iterator end;

    for(auto it = begin; it != end; it++) {

        //cout << *it << endl;

        // FIXME: Inspect here if something weird happens.

        string destinationMac(*it);
        for(auto& c : destinationMac) c = toupper(c);

        DestinationMacs.push_back(destinationMac);

    }

}
