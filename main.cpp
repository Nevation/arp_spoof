#include "header.h"
#include <iostream>
#include <thread>
using namespace std;


int main(int argc, char* argv[]){
    if (argc % 2 == 1 || argc < 4){
        printf("Usage: ./send_arp <interface> <sender ip 1> <target ip 1> [<sender ip 2> <target ip 2> ...]\n");
        return -1;
    }

    for(int i=2; i<argc; i++){
        if(!check_ipv4(argv[i])){
            printf("Check IP: %s\n", argv[i]);
            return -2;
        }
    }

    int cnt = (argc - 2) / 2;
    thread* td = new thread[cnt];
    arp_spoofing** ArpSpoofing = new arp_spoofing*[cnt];

    for (int i=0; i<cnt; i++) {
        ArpSpoofing[i] = new arp_spoofing(argv[1], argv[i * 2 + 2], argv[i * 2 + 3]);
    }

    for(int i=0;i<cnt;i++){
        td[i] = thread(&arp_spoofing::ExecuteArpSpoofing, ArpSpoofing[i]);
    }

    for (int i=0; i<cnt; i++){
        td[i].join();
    }

    for (int i=0;i<cnt; i++) delete ArpSpoofing[i];
    delete[] ArpSpoofing;

    return 0;
}
