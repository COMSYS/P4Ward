/* -*- P4_16 -*- */
#ifndef __PROTOCOL_UDP__
#define __PROTOCOL_UDP__

header udp_h {
    bit<16> src_port;
    bit<16> dst_port;
    bit<16> datagram_length;
    bit<16> hdr_checksum;
}

const bit<16> UDP_HEADER_SIZE = 8;

#endif