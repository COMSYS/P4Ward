/* -*- P4_16 -*- */
#ifndef __PROTOCOL_HELPER__
#define __PROTOCOL_HELPER__

struct le_16b_t {
    bit<8> part_2;
    bit<8> part_1;
}

struct le_32b_t {
    bit<8> part_4;
    bit<8> part_3;
    bit<8> part_2;
    bit<8> part_1;
}

#endif