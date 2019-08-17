#pragma once
#include "header.h"

struct arp_spoofing{
public:
    arp_spoofing();
    ~arp_spoofing();
    arp_spoofing(const char* dev, const char* sender, char* target);
    void ExecuteArpSpoofing();
private:
    char* Dev;

    pcap_t* handle;

    struct Address* Attacker;
    struct Address* Sender;
    struct Address* Target;

    void Init(const char* sender, const char* target);
    Address* SetAddress(const u_char* ip);
    void SetAttacker();

    struct arp_packet* MakeRequestPacket(const u_char* ip);
    struct arp_packet* MakeAttackPacket();
};

