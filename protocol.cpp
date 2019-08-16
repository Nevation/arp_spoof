#include "protocol.h"

Protocol::Protocol() {
}
Protocol::~Protocol() {
}
Protocol::Protocol(u_char* type, u_char size) {
    ProtocolType[0] = type[0]; ProtocolType[1] = type[1];
    ProtocolSize = size;
}
Protocol::Protocol(const u_char* packet){
    ProtocolType[0] = packet[0]; ProtocolType[1] = packet[1];
    ProtocolSize = packet[3];
}
u_char* Protocol::GetProtocolType() {
    return ProtocolType;
}
u_char Protocol::GetProtocolSize() {
    return ProtocolSize;
}
