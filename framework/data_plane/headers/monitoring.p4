/* -*- P4_16 -*- */
#ifndef __PROTOCOL_MONITORING__
#define __PROTOCOL_MONITORING__

#include "ethernet.p4"

header monitoring_h {
    bit<48> in_timestamp;
    bit<48> in_timestamp_recirculation;
    bit<48> out_timestamp;
    ether_type_t ether_type;
}

#endif