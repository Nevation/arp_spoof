#pragma once
#include "header.h"

struct Hardware
{
public:
    Hardware();
    ~Hardware();
    Hardware(const u_char* type, const u_char size);
    Hardware(const u_char* packet);
    u_char* GetHardwareType();
    u_char GetHardwareSize();
private:
    u_char HardwareType[2];
    u_char HardwareSize;
};
