/* -*- P4_16 -*- */
#ifndef __PROTOCOL_ICMP__
#define __PROTOCOL_ICMP__

header icmp_h {
    bit<8>  type;
    bit<8>  code;
    bit<16> checksum;
    // bit<32> rest;
}

#endif