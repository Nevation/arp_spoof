#include "ethernet_header.h"

ethernet_header::ethernet_header(){
    Destination = new u_char[MAC_SIZE];
    Source = new u_char[MAC_SIZE];
    Type = new u_char[U_CHAR_SIZE_2];
}
ethernet_header::~ethernet_header(){
    delete[] Destination;
    delete[] Source;
    delete[] Type;
}
ethernet_header::ethernet_header(const u_char* dest, const u_char* source, const u_char* type){
    Destination = new u_char[MAC_SIZE];
    Source = new u_char[MAC_SIZE];
    Type = new u_char[U_CHAR_SIZE_2];
    memcpy(Destination, dest, MAC_SIZE);
    memcpy(Source, source, MAC_SIZE);
    memcpy(Type, type, U_CHAR_SIZE_2);

}
ethernet_header::ethernet_header(const u_char* packet){
    Destination = new u_char[MAC_SIZE];
    Source = new u_char[MAC_SIZE];
    Type = new u_char[U_CHAR_SIZE_2];
    memcpy(Destination, &packet[0], MAC_SIZE);
    memcpy(Source, &packet[6], MAC_SIZE);
    memcpy(Type, &packet[12], U_CHAR_SIZE_2);
}
u_char* ethernet_header::GetDestionation(){
    return Destination;
}
u_char* ethernet_header::GetSoruce(){
    return Source;
}
u_char* ethernet_header::GetType(){
    return Type;
}
u_char* ethernet_header::ToPacket(){
    u_char* packet = new u_char[14];
    memcpy(&packet[0], Destination, 6);
    memcpy(&packet[6], Source, 6);
    memcpy(&packet[12], Type, 2);
    return packet;
}
