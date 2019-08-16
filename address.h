#pragma once
#include "header.h"

struct Address
{
public:
    Address();
    ~Address();
    Address(const u_char* mac, const u_char* ip);
    Address(const u_char* packet);
    u_char* GetMacAddress();
    u_char* GetIpAddress();
    u_char* ToPacket();
private:
    u_char* MacAddress;
    u_char* IpAddress;
};

