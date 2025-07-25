/* -*- P4_16 -*- */
#ifndef __CONTROLS_ICMP_VALIDATOR__
#define __CONTROLS_ICMP_VALIDATOR__

#include <core.p4>
#include <tna.p4>

#include "../../types.p4"

const bit<8> ICMP_FLAG_NONE = 0x00;
const bit<8> ICMP_FLAG_DISABLE_ECHO = 0x01;
const bit<8> ICMP_FLAG_DISABLE_DESTINATION_UNREACHABLE = 0x02;
const bit<8> ICMP_FLAG_DISABLE_REDIRECT = 0x04;
const bit<8> ICMP_FLAG_DISABLE_ROUTER_ADVERTISEMENT = 0x08;
const bit<8> ICMP_FLAG_DISABLE_ROUTER_SOLICITATION = 0x10;
const bit<8> ICMP_FLAG_DISABLE_TIME_EXCEEDED = 0x20;
const bit<8> ICMP_FLAG_DISABLE_BAD_HEADER = 0x40;
const bit<8> ICMP_FLAG_DISABLE_TIMESTAMP = 0x80;

control IcmpValidatorControl(
    inout egress_headers_t headers,
    inout egress_metadata_t meta,
    in egress_intrinsic_metadata_t intr_meta,
    in egress_intrinsic_metadata_from_parser_t parser_meta,
    inout egress_intrinsic_metadata_for_deparser_t deparser_meta,
    inout egress_intrinsic_metadata_for_output_port_t output_port_meta) {

    action set_flags(bit<8> validator_mask, bit<8> protocol_validator_mask) {
        meta.validator_mask = meta.validator_mask | validator_mask;
        meta.protocol_validator_mask = meta.protocol_validator_mask | protocol_validator_mask;
    }
    
    action drop() {
        deparser_meta.drop_ctl = 1;
        exit;
    }

    table icmp_commands {
        key = {
            headers.icmp.type: exact;
        }
        actions = {
            set_flags;
            @defaultonly drop();
        }
        size = 12;
        default_action = drop();
        const entries = {
            0x00: set_flags(VALIDATOR_FLAG_DISABLE_REPLY,   ICMP_FLAG_DISABLE_ECHO);                    // Echo Reply
            0x03: set_flags(VALIDATOR_FLAG_NONE,            ICMP_FLAG_DISABLE_DESTINATION_UNREACHABLE); // Destination Unreachable
            0x05: set_flags(VALIDATOR_FLAG_NONE,            ICMP_FLAG_DISABLE_REDIRECT);                // Redirect Message
            0x08: set_flags(VALIDATOR_FLAG_DISABLE_REQUEST, ICMP_FLAG_DISABLE_ECHO);                    // Echo Request
            0x09: set_flags(VALIDATOR_FLAG_NONE,            ICMP_FLAG_DISABLE_ROUTER_ADVERTISEMENT);    // Router Advertisement
            0x0a: set_flags(VALIDATOR_FLAG_NONE,            ICMP_FLAG_DISABLE_ROUTER_SOLICITATION);     // Router Discovery
            0x0b: set_flags(VALIDATOR_FLAG_NONE,            ICMP_FLAG_DISABLE_TIME_EXCEEDED);           // Time Exceeded
            0x0c: set_flags(VALIDATOR_FLAG_NONE,            ICMP_FLAG_DISABLE_BAD_HEADER);              // Parameter Problem: Bad IP header
            0x0d: set_flags(VALIDATOR_FLAG_DISABLE_REQUEST, ICMP_FLAG_DISABLE_TIMESTAMP);               // Timestamp Request
            0x0e: set_flags(VALIDATOR_FLAG_DISABLE_REPLY,   ICMP_FLAG_DISABLE_TIMESTAMP);               // Timestamp Reply
            0x2a: set_flags(VALIDATOR_FLAG_DISABLE_REQUEST, ICMP_FLAG_DISABLE_ECHO);                    // Extended Echo Request
            0x2b: set_flags(VALIDATOR_FLAG_DISABLE_REPLY,   ICMP_FLAG_DISABLE_ECHO);                    // Extended Echo Reply
        }
    }

    apply {
        // 1: Drop packets with invalid icmp commands
        icmp_commands.apply();
    }

}

#endif