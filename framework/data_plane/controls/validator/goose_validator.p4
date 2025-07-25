/* -*- P4_16 -*- */
#ifndef __CONTROLS_GOOSE_VALIDATOR__
#define __CONTROLS_GOOSE_VALIDATOR__

#include <core.p4>
#include <tna.p4>

#include "../../types.p4"

const bit<8> GOOSE_FLAG_NONE = 0x00;
const bit<8> GOOSE_FLAG_VERIFY_APP_ID = 0x01;

control GOOSEValidatorControl(
    inout egress_headers_t headers,
    inout egress_metadata_t meta,
    in egress_intrinsic_metadata_t intr_meta,
    in egress_intrinsic_metadata_from_parser_t parser_meta,
    inout egress_intrinsic_metadata_for_deparser_t deparser_meta,
    inout egress_intrinsic_metadata_for_output_port_t output_port_meta) {

    action set_app_id_flag() {
        meta.protocol_validator_mask = meta.protocol_validator_mask | GOOSE_FLAG_VERIFY_APP_ID;
    }
    
    action drop() {
        deparser_meta.drop_ctl = 1;
        exit;
    }

    table goose_app_ids {
        key = {
            headers.egress_meta.ace_from_id: exact @name("ace_id");
            headers.goose.app_id: exact @name("app_id");
        }
        actions = {
            NoAction;
            @defaultonly set_app_id_flag();
        }
        size = 512;
        default_action = set_app_id_flag();
    }

    apply {
        // 1: Drop packets with unauthorized app ids
        goose_app_ids.apply();
    }

}

#endif