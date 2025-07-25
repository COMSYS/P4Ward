/* -*- P4_16 -*- */
#ifndef __PROTOCOL_GOOSE__
#define __PROTOCOL_GOOSE__

header goose_h {
    bit<16> app_id;

    bit<16> length;

    bit<16> reserved_1;
    bit<16> reserved_2;
}

#endif