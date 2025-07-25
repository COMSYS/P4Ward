/* -*- P4_16 -*- */
#ifndef __PROTOCOL_ETHERNET__
#define __PROTOCOL_ETHERNET__

typedef bit<48> MacAddress_t;

enum bit<16> ether_type_t {
    IPV4 = 0x0800,
    ARP = 0x0806,
    IPV6 = 0x86dd,
    VLAN = 0x8100,
    EAPOL = 0x888e,
    GOOSE = 0x88b8,
    MONITORING = 0xf001,
    CUSTOM_EAP = 0xff01
}

header ethernet_h {
    MacAddress_t dst_address;
    MacAddress_t src_address;
    ether_type_t ether_type;
}

header vlan_h {
    bit<3> pcp;
    bit<1> dei;
    bit<12> vid;
    ether_type_t ether_type;
}

#endif