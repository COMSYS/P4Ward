/* -*- P4_16 -*- */
#ifndef __CONTROLS_ENIP_VALIDATOR__
#define __CONTROLS_ENIP_VALIDATOR__

#include <core.p4>
#include <tna.p4>

#include "../../types.p4"

control EnipValidatorControl(
    inout egress_headers_t headers,
    inout egress_metadata_t meta,
    in egress_intrinsic_metadata_t intr_meta,
    in egress_intrinsic_metadata_from_parser_t parser_meta,
    inout egress_intrinsic_metadata_for_deparser_t deparser_meta,
    inout egress_intrinsic_metadata_for_output_port_t output_port_meta) {
    
    action drop() {
        deparser_meta.drop_ctl = 1;
        exit;
    }

    table enip_commands {
        key = {
            headers.enip.command: exact;
        }
        actions = {
            NoAction;
            @defaultonly drop();
        }
        size = 16;
        default_action = drop();
        const entries = {
            // Little Endian is used -> byte order is inverted
            0x0000: NoAction(); // NOOP
            0x0400: NoAction(); // List Services
            0x6300: NoAction(); // List Identity
            0x6400: NoAction(); // List Interfaces
            0x6500: NoAction(); // Register Session
            0x6600: NoAction(); // Unregister Session
            0x6f00: NoAction(); // Send RR Data
            0x7000: NoAction(); // Send Unit Data
            0x7200: NoAction(); // Indicate Status
            0x7300: NoAction(); // Cancel
        }
    }

    apply {
        // 1: Drop packets with invalid payload lengths
        bit<16> enip_payload_length = headers.enip.payload_length.part_1 ++ headers.enip.payload_length.part_2; // Convert little endian to big endian (see enip header)
        enip_payload_length = enip_payload_length + ENIP_HEADER_SIZE;
        if (enip_payload_length != headers.egress_meta.payload_length) {
            drop();
        }

        // 2: Drop packets with invalid enip commands
        enip_commands.apply();
    }

}

#endif