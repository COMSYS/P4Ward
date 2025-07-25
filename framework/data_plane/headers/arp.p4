/* -*- P4_16 -*- */
#ifndef __PROTOCOL_ARP__
#define __PROTOCOL_ARP__

#include "ethernet.p4"
#include "ipv4.p4"

enum bit<16> arp_opcode_t {
    REQUEST = 1,
    REPLY = 2
}

header arp_h {
    bit<16> hardware_address_type;
    ether_type_t protocol_type;
    bit<8> hardware_address_length;
    bit<8> protocol_length;
    arp_opcode_t opcode;
    MacAddress_t src_mac;
    Ipv4Address_t src_ip;
    MacAddress_t dst_mac;
    Ipv4Address_t dst_ip;
}

#endif