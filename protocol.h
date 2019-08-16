#pragma once
#include "header.h"

struct Protocol
{
public:
    Protocol();
    ~Protocol();
    Protocol(u_char* type, u_char size);
    Protocol(const u_char* packet);
    u_char* GetProtocolType();
    u_char GetProtocolSize();
private:
    u_char ProtocolType[2];
    u_char ProtocolSize;
};
