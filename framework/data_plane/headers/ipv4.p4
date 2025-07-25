/* -*- P4_16 -*- */
#ifndef __PROTOCOL_IPV4__
#define __PROTOCOL_IPV4__

typedef bit<32> Ipv4Address_t;

enum bit<8> ipv4_protocol_t {
    ICMP = 1,
    IGMP = 2,
    TCP = 6,
    UDP = 17
}

const bit<128> IPV4_TO_IPV6 = 128w0x00000000000000000000FFFF00000000;

header ipv4_h {
    bit<4> version;
    bit<4> ihl;
    bit<8> tos;
    bit<16> total_length;
    bit<16> identification;
    bit<3> flags;
    bit<13> fragment_offset;
    bit<8> ttl;
    ipv4_protocol_t protocol;
    bit<16> checksum;
    Ipv4Address_t src_address;
    Ipv4Address_t dst_address;
}

const bit<16> IPV4_HEADER_SIZE = 20;

#endif