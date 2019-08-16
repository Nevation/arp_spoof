#include "address.h"

Address::Address() {
    MacAddress = new u_char[MAC_SIZE];
    IpAddress = new u_char[IP_SIZE];
}
Address::~Address() {
    delete[] MacAddress;
    delete[] IpAddress;
}
Address::Address(const u_char* mac, const u_char* ip) {
    MacAddress = new u_char[MAC_SIZE];
    IpAddress = new u_char[IP_SIZE];
    memcpy(MacAddress, mac, MAC_SIZE);
    memcpy(IpAddress, ip, IP_SIZE);

}
Address::Address(const u_char* packet){
    MacAddress = new u_char[MAC_SIZE];
    IpAddress = new u_char[IP_SIZE];
    memcpy(MacAddress, &packet[0], MAC_SIZE);
    memcpy(IpAddress, &packet[MAC_SIZE], IP_SIZE);
}
u_char* Address::GetMacAddress() {
    return MacAddress;
}
u_char* Address::GetIpAddress() {
    return IpAddress;
}

u_char* Address::ToPacket() {
    u_char* packet = new u_char[10];
    memcpy(&packet[0], MacAddress, MAC_SIZE);
    memcpy(&packet[MAC_SIZE], IpAddress, IP_SIZE);
    return packet;
}

