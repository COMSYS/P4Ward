/* -*- P4_16 -*- */
#ifndef __PROTOCOL_IPV6__
#define __PROTOCOL_IPV6__

typedef bit<128> Ipv6Address;

enum bit<8> ipv6_protocol_t {
    ICMP = 1,
    IGMP = 2,
    TCP = 6,
    UDP = 17
}

header ipv6_h {
    bit<4> version;
    bit<8> traffic_class;
    bit<20> flow_label;
    bit<16> payload_length;
    bit<8> next_header;
    bit<8> hop_limit;
    Ipv6Address src_address;
    Ipv6Address dst_address;
}

const bit<32> IPV6_HEADER_SIZE = 40;

#endif