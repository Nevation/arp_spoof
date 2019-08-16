#include "arp_header.h"

arp_header::arp_header() {
    hardware = new Hardware();
    protocol = new Protocol();
    Opcode = new u_char[U_CHAR_SIZE_2];
    Sender = new Address();
    Target = new Address();
}
arp_header::~arp_header() {
    delete hardware;
    delete protocol;
    delete[] Opcode;
    delete Sender;
    delete Target;
}
arp_header::arp_header(Hardware* hard, Protocol* proto, u_char* opcode, Address* sender, Address* target) {
    hardware = new Hardware(hard->GetHardwareType(), hard->GetHardwareSize());
    protocol = new Protocol(proto->GetProtocolType(), proto->GetProtocolSize());
    Opcode = new u_char[U_CHAR_SIZE_2];
    memcpy(Opcode, opcode, U_CHAR_SIZE_2);
    Sender = new Address(sender->GetMacAddress(), sender->GetIpAddress());
    Target = new Address(target->GetMacAddress(), target->GetIpAddress());
}
arp_header::arp_header(const u_char* packet){
    hardware = new Hardware(packet, packet[4]);
    protocol = new Protocol(&packet[2]);
    Opcode = new u_char[U_CHAR_SIZE_2];
    memcpy(Opcode, &packet[6], 2);
    Sender = new Address(&packet[8]);
    Target = new Address(&packet[18]);
}
u_char* arp_header::ToPacket(){
    u_char* packet = new u_char[28];
    memcpy(&packet[0], hardware->GetHardwareType(), U_CHAR_SIZE_2);
    memcpy(&packet[2], protocol->GetProtocolType(), U_CHAR_SIZE_2);
    packet[4]=hardware->GetHardwareSize();
    packet[5]=protocol->GetProtocolSize();
    memcpy(&packet[6], Opcode, U_CHAR_SIZE_2);
    memcpy(&packet[8], Sender->ToPacket(), MAC_SIZE + IP_SIZE);
    memcpy(&packet[18], Target->ToPacket(), MAC_SIZE + IP_SIZE);
    return packet;
}
Hardware* arp_header::GetHardware() {
    return hardware;
}
Protocol* arp_header::GetProtocol() {
    return protocol;
}
u_char* arp_header::GetOpcode() {
    return Opcode;
}
Address* arp_header::GetSenderAddress() {
    return Sender;
}
Address* arp_header::GetTargetAddress() {
    return Target;
}
