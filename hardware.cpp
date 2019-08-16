#include "hardware.h"

Hardware::Hardware() {
}
Hardware::~Hardware() {
}
Hardware::Hardware(const u_char* type, const u_char size){
    HardwareType[0] = type[0]; HardwareType[1] = type[1];
    HardwareSize = size;
}
Hardware::Hardware(const u_char* packet){
    HardwareType[0] = packet[0]; HardwareType[1] = packet[1];
    HardwareSize = packet[4];
}
u_char* Hardware::GetHardwareType() {
    return HardwareType;
}
u_char Hardware::GetHardwareSize() {
    return HardwareSize;
}
