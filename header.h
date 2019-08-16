#pragma once

#include <pcap.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#define U_CHAR_SIZE_2 2
#define MAC_SIZE 6
#define IP_SIZE 4

#include "address.h"
#include "arp_header.h"
#include "arp_packet.h"
#include "arp_spoofing.h"
#include "etc_function.h"
#include "ethernet_header.h"
#include "hardware.h"
#include "protocol.h"

