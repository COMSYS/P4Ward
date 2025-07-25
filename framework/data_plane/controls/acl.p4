/* -*- P4_16 -*- */
#ifndef __CONTROLS_ACL__
#define __CONTROLS_ACL__

#include <core.p4>
#include <tna.p4>

#include "../types.p4"

typedef bit<16> bloom_filter_position_t;
#define BLOOM_FILTER_SIZE 65536

typedef bit<16> update_bloom_filter_position_t;
#define UPDATE_BLOOM_FILTER_SIZE 65536

enum bit<1> initiation_direction_t {
    FROM_DEVICE = 0,
    TO_DEVICE = 1
}

struct ternary_direction_t {
    bit<1> set;
    initiation_direction_t direction;
}

control AclControl(
    inout ingress_headers_t headers,
    inout ingress_metadata_t meta,
    in ingress_intrinsic_metadata_t intr_meta,
    in ingress_intrinsic_metadata_from_parser_t parser_meta,
    inout ingress_intrinsic_metadata_for_deparser_t deparser_meta,
    inout ingress_intrinsic_metadata_for_tm_t traffic_manager_meta) {

    bit<1> use_connection_filtering = 0;

    action deny() {
        deparser_meta.drop_ctl = 1;
        exit; // Exit ingress stage
    }

    ternary_direction_t policy_direction_from = { 0, initiation_direction_t.FROM_DEVICE };

    action allow_from(bit<16> ace_id, protocol_validator_id_t protocol_validator, bit<8> validator_flags, bit<8> protocol_validator_flags) {
        meta.ace_from_id = ace_id;

        meta.from_protocol_id = protocol_validator;
        meta.validator_flags = meta.validator_flags | validator_flags;
        meta.protocol_validator_flags = meta.protocol_validator_flags | protocol_validator_flags;
    }

    action allow_filtered_from(bit<16> ace_id, protocol_validator_id_t protocol_validator, bit<8> validator_flags, bit<8> protocol_validator_flags, initiation_direction_t direction) {
        meta.ace_from_id = ace_id;

        meta.from_protocol_id = protocol_validator;
        meta.validator_flags = meta.validator_flags | validator_flags;
        meta.protocol_validator_flags = meta.protocol_validator_flags | protocol_validator_flags;

        use_connection_filtering  = 1;
        policy_direction_from = { 1, direction };
    }

    table acl_from_device {
        key = {
            meta.src_id: exact @name("src_id");
            meta.src_port: exact @name("src_port");
            meta.src_sub_id: exact @name("src_controller");
            meta.src_manufacturer_id: exact @name("src_manufacturer");
            meta.src_model_id: exact @name("src_model");
            meta.dst_ip_address: ternary @name("dst_ip_address");
            meta.dst_port: exact @name("dst_port");
            meta.dst_sub_id: exact @name("dst_controller");
            meta.dst_manufacturer_id: exact @name("dst_manufacturer");
            meta.dst_model_id: exact @name("dst_model");
            meta.protocol_flags: ternary @name("protocol");
        }
        actions = {
            allow_from;
            allow_filtered_from;
            deny;
        }
        size = 1024;
        const default_action = deny();
    }

    ternary_direction_t policy_direction_to = { 0, initiation_direction_t.TO_DEVICE };

    action allow_to(bit<16> ace_id, protocol_validator_id_t protocol_validator, bit<8> validator_flags, bit<8> protocol_validator_flags) {
        meta.ace_to_id = ace_id;

        meta.to_protocol_id = protocol_validator;
        meta.validator_flags = meta.validator_flags | validator_flags;
        meta.protocol_validator_flags = meta.protocol_validator_flags | protocol_validator_flags;
    }

    action allow_filtered_to(bit<16> ace_id, protocol_validator_id_t protocol_validator, bit<8> validator_flags, bit<8> protocol_validator_flags, initiation_direction_t direction) {
        meta.ace_to_id = ace_id;
        
        meta.to_protocol_id = protocol_validator;
        meta.validator_flags = meta.validator_flags | validator_flags;
        meta.protocol_validator_flags = meta.protocol_validator_flags | protocol_validator_flags;

        use_connection_filtering  = 1;
        policy_direction_to = { 1, direction };
    }

    table acl_to_device {
        key = {
            meta.src_ip_address: ternary @name("src_ip_address");
            meta.src_port: exact @name("src_port");
            meta.src_sub_id: exact @name("src_controller");
            meta.src_manufacturer_id: exact @name("src_manufacturer");
            meta.src_model_id: exact @name("src_model");
            meta.dst_id: exact @name("dst_id");
            meta.dst_port: exact @name("dst_port");
            meta.dst_sub_id: exact @name("dst_controller");
            meta.dst_manufacturer_id: exact @name("dst_manufacturer");
            meta.dst_model_id: exact @name("dst_model");
            meta.protocol_flags: ternary @name("protocol");
        }
        actions = {
            allow_to;
            allow_filtered_to;
            deny;
        }
        size = 1024;
        const default_action = deny();
    }
    
    Hash<bit<32>>(HashAlgorithm_t.CRC32) hash;

    Register<bit<1>, bloom_filter_position_t>(BLOOM_FILTER_SIZE) bloom_filter_1;
    Register<bit<1>, bloom_filter_position_t>(BLOOM_FILTER_SIZE) bloom_filter_2;
    Register<bit<1>, update_bloom_filter_position_t>(UPDATE_BLOOM_FILTER_SIZE) update_bloom_filter;

    RegisterAction<bit<1>, update_bloom_filter_position_t, bit<1>>(update_bloom_filter) check_update_filter = {
        void apply(inout bit<1> register_data, out bit<1> result) {
            result = register_data;
            register_data = 0;
        }
    };

    apply {
        if (meta.valid_src) {
            acl_from_device.apply();
        }
        
        if (meta.valid_dst) {
            acl_to_device.apply();
        }

        // To allow proper bloom filter functioning
        // Two bits are raised using recirculation, but only one bit is used for filtering
        bit<256> ip_addresses;
        bit<32> ports;

        if (headers.recirculation.isValid()) {
            ip_addresses = meta.src_ip_address ++ meta.dst_ip_address;
            ports = meta.src_port ++ meta.dst_port;
        }
        else {
            ip_addresses = meta.dst_ip_address ++ meta.src_ip_address;
            ports = meta.dst_port ++ meta.src_port;
        }

        bit<32> flow_id = hash.get(
            {
                ip_addresses,
                ports
            });
        bloom_filter_position_t flow_id_1 = flow_id[31:16];
        bloom_filter_position_t flow_id_2 = flow_id[15:0];
                
        if (use_connection_filtering == 1) {
            if (policy_direction_from.set == 1 && policy_direction_to.set == 1 && 
                policy_direction_from.direction == policy_direction_to.direction) {
                // Contradicting policies: [-> | <-] or [<- | ->]
                deny();
            }
            else if ((policy_direction_from.set == 0 || policy_direction_from.direction == initiation_direction_t.FROM_DEVICE) && 
                (policy_direction_to.set == 0 || policy_direction_to.direction == initiation_direction_t.TO_DEVICE)) {
                // Direction allowed by policy, i.e. [-> | ->], [-> | <->] or [<-> | ->]

                // Raise bloom filter bits on SYN packets
                if (headers.tcp.flags[1:1] == 1) {
                    // // Read from bloom filter
                    // bit<1> bloom_register_1 = bloom_filter_1.read(flow_id_1);
                    // bit<1> bloom_register_2 = bloom_filter_2.read(flow_id_2);

                    // if (bloom_register_1 == 0 || bloom_register_2 == 0) {
                        bloom_filter_1.write(flow_id_1, 1);
                        bloom_filter_2.write(flow_id_2, 1);

                        if (headers.recirculation.isValid()) 
                        {
                            // Copy to CPU
                            traffic_manager_meta.copy_to_cpu = 1;
                        }
                        else {
                            // Initialize recirculation header
                            headers.recirculation.setValid();
                            headers.recirculation.port = meta.port;

                            // Recirculate
                            traffic_manager_meta.ucast_egress_port = meta.port[8:7] ++ RECIRCULATION_PORT;
                            traffic_manager_meta.bypass_egress = 1;
                            exit; // Force immediate recirculation
                        }
                    // }
                }
                else if (headers.tcp.flags[0:0] == 1) {
                    // Copy to CPU
                    traffic_manager_meta.copy_to_cpu = 1;
                }
            }
            else {
                // Direction not allowed by policy, i.e. [<- | <-], [<- | <->] or [<-> | <-]

                // Read from bloom filter
                bit<1> bloom_register_1 = bloom_filter_1.read(flow_id_1);
                bit<1> bloom_register_2 = bloom_filter_2.read(flow_id_2);

                if (bloom_register_1 == 0 || bloom_register_2 == 0) {
                    deny();
                }
                else if (headers.tcp.flags[0:0] == 1) {
                    // Copy to CPU
                    traffic_manager_meta.copy_to_cpu = 1;
                }
            }
            

            if (check_update_filter.execute((update_bloom_filter_position_t)flow_id_1) == 1) {
                // Copy to CPU
                traffic_manager_meta.copy_to_cpu = 1;
            }
        }
    }
}

#endif
