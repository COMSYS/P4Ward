/* -*- P4_16 -*- */
#ifndef __PROTOCOL_TCP__
#define __PROTOCOL_TCP__

// struct tcp_flags_t {
// }

header tcp_h {
    bit<16> src_port;
    bit<16> dst_port;
    bit<32> seq_number;
    bit<32> ack_number;
    bit<4> data_offset;
    bit<4> reserved;
    
    // TCP flags:    | cwr | ece | urg | ack | psh | rst | syn | fin |
    // Bit position: |  7  |  6  |  5  |  4  |  3  |  2  |  1  |  0  |
    bit<8> flags;
    bit<16> window_size;
    bit<16> hdr_checksum;
    bit<16> urgent_pointer;
}

const bit<16> TCP_HEADER_SIZE = 20;

header tcp_option_word_h {
    bit<32> option;
}

#endif