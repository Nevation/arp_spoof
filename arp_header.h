#pragma once
#include "header.h"

struct arp_header
{
public:
    arp_header();
    ~arp_header();
    arp_header(struct Hardware* hard, struct Protocol* proto,
        u_char* opcode, struct Address* sender, struct Address* target);
    arp_header(const u_char* packet);
    struct Hardware* GetHardware();
    struct Protocol* GetProtocol();
    u_char* GetOpcode();
    struct Address* GetSenderAddress();
    struct Address* GetTargetAddress();
    u_char* ToPacket();
private:
    struct Hardware* hardware;
    struct Protocol* protocol;
    u_char* Opcode;
    struct Address* Sender;
    struct Address* Target;
};
