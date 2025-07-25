/* -*- P4_16 -*- */
#ifndef __CONTROLS_AUTH__
#define __CONTROLS_AUTH__

#include <core.p4>
#include <tna.p4>

#include "../types.p4"

typedef bit<16> eap_id_t;

control AuthControl(
    inout ingress_headers_t headers,
    inout ingress_metadata_t meta,
    in ingress_intrinsic_metadata_t intr_meta,
    in ingress_intrinsic_metadata_from_parser_t parser_meta,
    inout ingress_intrinsic_metadata_for_deparser_t deparser_meta,
    inout ingress_intrinsic_metadata_for_tm_t traffic_manager_meta) {
    
    Hash<eap_id_t>(HashAlgorithm_t.CRC32) hash;


    Register<bit<8>, eap_id_t>(65536) kdf_type_register;
    Register<eap_seed_t, eap_id_t>(65536) seed_register;
    Register<bit<16>, eap_id_t>(65536) position_register;
    Register<bit<8>, eap_id_t>(65536) remaining_steps_register;

    Register<eap_sequence_id_t, eap_id_t>(65536) sequence_id_register;
    Register<bit<32>, eap_id_t>(65536) otp_first_register;
    Register<bit<32>, eap_id_t>(65536) otp_second_register;
    
    // Gives the position of the current OTP and increments to the next position, the control plane has to change this value if new otps are added
    RegisterAction<bit<16>, eap_id_t, bit<16>>(position_register) read_position = {
        void apply(inout bit<16> register_data, out bit<16> result) {
            result = register_data;
            register_data = register_data - 1;
        }
    };

    // Read OTP authentication status
    RegisterAction<bit<8>, eap_id_t, bit<8>>(remaining_steps_register) read_remaining_steps = {
        void apply(inout bit<8> register_data, out bit<8> result) {
            result = register_data;
            if (register_data > 0) {
                register_data = register_data - 1;
            }
        }
    };

    // Reset OTP authentication status
    RegisterAction<bit<8>, eap_id_t, bit<8>>(remaining_steps_register) reset_remaining_steps = {
        void apply(inout bit<8> register_data) {
            register_data = 0;
        }
    };

    action send_to_control_plane(eap_metadata_type_t type) {
        headers.ethernet.ether_type = ether_type_t.CUSTOM_EAP;

        headers.eap_metadata.setValid();
        headers.eap_metadata.type = type;
        headers.eap_metadata.port = (bit<16>)intr_meta.ingress_port;

        traffic_manager_meta.ucast_egress_port = CPU_PORT;
        traffic_manager_meta.bypass_egress = 1;
        exit; // Exit ingress stage
    }

    action send_back() {
        MacAddress_t temp = headers.ethernet.dst_address;
        headers.ethernet.dst_address = headers.ethernet.src_address;
        headers.ethernet.src_address = temp;

        traffic_manager_meta.ucast_egress_port = intr_meta.ingress_port;
        traffic_manager_meta.bypass_egress = 1;
        exit; // Exit ingress stage
    }


    action send_otp_request(eap_sequence_id_t sequence_id, eap_seed_t seed) {
        headers.eap.code = eap_code_t.REQUEST;
        headers.eap.id = headers.eap.id + 1; // Increment request id

        headers.eap_otp.value_size = EAP_OTP_CHALLENGE_SIZE;
        headers.eap_otp.value_first = EAP_OTP_ID_1;
        headers.eap_otp.space_1 = 0x20; // WHITE SPACE
        headers.eap_otp.sequence_id = sequence_id;
        headers.eap_otp.space_2 = 0x20; // WHITE SPACE
        headers.eap_otp.seed = seed;
        headers.eap_otp.space_3 = 0x20; // WHITE SPACE
        
        send_back();
    }

    // action send_otp_md5_request(eap_sequence_id_t sequence_id, eap_seed_t seed) {
    //     headers.eap_otp.value_second = EAP_OTP_MD5_ID_2;
    //     send_otp_request(sequence_id, seed);
    // }

    // action send_otp_sha1_request(eap_sequence_id_t sequence_id, eap_seed_t seed) {
    //     headers.eap_otp.value_second = EAP_OTP_SHA1_ID_2;
    //     send_otp_request(sequence_id, seed);
    // }

    // action send_otp_sha2_request(eap_sequence_id_t sequence_id, eap_seed_t seed) {
    //     headers.eap_otp.value_second = EAP_OTP_SHA2_ID_2;
    //     send_otp_request(sequence_id, seed);
    // }

    // action send_otp_sha3_request(eap_sequence_id_t sequence_id, eap_seed_t seed) {
    //     headers.eap_otp.value_second = EAP_OTP_SHA3_ID_2;
    //     send_otp_request(sequence_id, seed);
    // }

    action signal_otp_success() {
        headers.eap_otp.value_size = EAP_OTP_CHALLENGE_SIZE;
        headers.eap_otp.value_first = 0;
        headers.eap_otp.value_second = 0;
        headers.eap_otp.space_1 = 0;
        headers.eap_otp.sequence_id = 0;
        headers.eap_otp.space_2 = 0;
        headers.eap_otp.seed = 0;
        headers.eap_otp.space_3 = 0;

        send_to_control_plane(eap_metadata_type_t.SUCCESS);
    }

    action signal_otp_failure() {
        headers.eap_otp.value_size = EAP_OTP_CHALLENGE_SIZE;
        headers.eap_otp.value_first = 0;
        headers.eap_otp.value_second = 0;
        headers.eap_otp.space_1 = 0;
        headers.eap_otp.sequence_id = 0;
        headers.eap_otp.space_2 = 0;
        headers.eap_otp.seed = 0;
        headers.eap_otp.space_3 = 0;

        send_to_control_plane(eap_metadata_type_t.FAILURE);
    }

    action signal_otp_error() {
        headers.eap_otp.value_size = EAP_OTP_CHALLENGE_SIZE;
        headers.eap_otp.value_first = 0;
        headers.eap_otp.value_second = 0;
        headers.eap_otp.space_1 = 0;
        headers.eap_otp.sequence_id = 0;
        headers.eap_otp.space_2 = 0;
        headers.eap_otp.seed = 0;
        headers.eap_otp.space_3 = 0;

        send_to_control_plane(eap_metadata_type_t.ERROR);
    }

    action signal_md5_response() {
        // EAP MD5 can only be handled on the control plane
        send_to_control_plane(eap_metadata_type_t.MESSAGE);
    }

    apply {
        if (headers.eap_otp.isValid()) {
            // Calculate EAP ID
            eap_id_t id = hash.get({ headers.ethernet.src_address });

            bit<8> kdf_type = kdf_type_register.read(id);
            eap_seed_t seed = seed_register.read(id);
            bit<16> position = read_position.execute(id);

            eap_sequence_id_t sequence_id = sequence_id_register.read(position); // Get next sequence id
            bit<32> otp_first = otp_first_register.read(position);
            bit<32> otp_second = otp_second_register.read(position);

            if (headers.eap_otp.value_first != otp_first) {
                reset_remaining_steps.execute(id);
                
                signal_otp_failure();
            }
            else if (headers.eap_otp.value_second != otp_second) {
                reset_remaining_steps.execute(id);

                signal_otp_failure();
            }
            else {
                bit<8> remaining_steps = read_remaining_steps.execute(id);

                if (remaining_steps == 1) {
                    signal_otp_success();
                }
                else if(remaining_steps == 0) {
                    signal_otp_error();
                }
                else {
                    if (kdf_type == 1) {
                        headers.eap_otp.value_second = EAP_OTP_MD5_ID_2;
                        send_otp_request(sequence_id, seed);
                    }
                    else if (kdf_type == 2) {
                        headers.eap_otp.value_second = EAP_OTP_SHA1_ID_2;
                        send_otp_request(sequence_id, seed);
                    }
                    else if (kdf_type == 3) {
                        headers.eap_otp.value_second = EAP_OTP_SHA2_ID_2;
                        send_otp_request(sequence_id, seed);
                    }
                    else if (kdf_type == 4) {
                        headers.eap_otp.value_second = EAP_OTP_SHA3_ID_2;
                        send_otp_request(sequence_id, seed);
                    }
                    else {
                        signal_otp_error();
                    }

                }
            }
        }
        else if (headers.eap_md5.isValid()) {
            signal_md5_response();
        }
        else {
            send_to_control_plane(eap_metadata_type_t.MESSAGE);
        }
    }
}

#endif
