/* -*- P4_16 -*- */
#ifndef __PROTOCOL_ENIP__
#define __PROTOCOL_ENIP__

#include "helper.p4"

// Note: ENIP uses little endian
// which means fields have to be interpreted the other way around
header enip_h {
    bit<16> command;
    le_16b_t payload_length;
    bit<32> session_handle;
    bit<32> status;
    bit<64> sender_context;
    bit<32> options;
}

const bit<16> ENIP_HEADER_SIZE = 24;

#endif