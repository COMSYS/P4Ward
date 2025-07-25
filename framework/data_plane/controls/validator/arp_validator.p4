/* -*- P4_16 -*- */
#ifndef __CONTROLS_ARP_VALIDATOR__
#define __CONTROLS_ARP_VALIDATOR__

#include <core.p4>
#include <tna.p4>

#include "../../types.p4"

control ArpValidatorControl(
    inout egress_headers_t headers,
    inout egress_metadata_t meta,
    in egress_intrinsic_metadata_t intr_meta,
    in egress_intrinsic_metadata_from_parser_t parser_meta,
    inout egress_intrinsic_metadata_for_deparser_t deparser_meta,
    inout egress_intrinsic_metadata_for_output_port_t output_port_meta) {

    action set_flags(bit<8> validator_mask) {
        meta.validator_mask = meta.validator_mask | validator_mask;
    }

    action drop() {
        deparser_meta.drop_ctl = 1;
        exit;
    }

    table arp_operations {
        key = {
            headers.arp.opcode: exact;
        }
        actions = {
            set_flags;
            @defaultonly drop();
        }
        size = 2;
        default_action = drop();
        const entries = {
            arp_opcode_t.REQUEST: set_flags(VALIDATOR_FLAG_DISABLE_REQUEST);
            arp_opcode_t.REPLY: set_flags(VALIDATOR_FLAG_DISABLE_REPLY);
        }
    }

    apply {
        // 1: Drop packets with invalid enip commands
        arp_operations.apply();
    }

}

#endif