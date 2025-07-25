/* -*- P4_16 -*- */
#ifndef __CONTROLS_DEVICE_VALIDATOR__
#define __CONTROLS_DEVICE_VALIDATOR__

#include <core.p4>
#include <tna.p4>

#include "../types.p4"

control DeviceValidatorControl(
    inout ingress_headers_t headers,
    inout ingress_metadata_t meta,
    in ingress_intrinsic_metadata_t intr_meta,
    in ingress_intrinsic_metadata_from_parser_t parser_meta,
    inout ingress_intrinsic_metadata_for_deparser_t deparser_meta,
    inout ingress_intrinsic_metadata_for_tm_t traffic_manager_meta) {

    bit<1> use_dst_ip = 0;

    // Src Meter
    bit<8> src_meter_tag = 8w0;
    Meter<bit<10>>(1024, MeterType_t.PACKETS) src_traffic_meter;

    // Dst Meter
    bit<1> use_dst_meter = 0;
    bit<10> dst_meter_id = 10w0;
    Meter<bit<10>>(1024, MeterType_t.PACKETS) dst_traffic_meter;


    action deny() {
        deparser_meta.drop_ctl = 1;
        exit; // Exit ingress stage
    }

    action ignore_src(bit<32> id, bit<32> sub_id, bit<16> manufacturer_id, bit<16> model_id) {
        meta.valid_src = false;
        meta.src_id = id;
        meta.src_sub_id = sub_id;
        meta.src_manufacturer_id = manufacturer_id;
        meta.src_model_id = model_id;
    }

    action match_src_device(bit<32> id, bit<32> sub_id, bit<16> manufacturer_id, bit<16> model_id) {
        meta.valid_src = true;
        meta.src_id = id;
        meta.src_sub_id = sub_id;
        meta.src_manufacturer_id = manufacturer_id;
        meta.src_model_id = model_id;
    }

    action match_src_device_limit(bit<10> meter_id, bit<32> id, bit<32> sub_id, bit<16> manufacturer_id, bit<16> model_id) {
        meta.valid_src = true;
        meta.src_id = id;
        meta.src_sub_id = sub_id;
        meta.src_manufacturer_id = manufacturer_id;
        meta.src_model_id = model_id;

        src_meter_tag = src_traffic_meter.execute(meter_id);
    }
    
    table device_src {
        key = {
            meta.port: exact @name("port");
            headers.ethernet.src_address: exact @name("mac_address");
            meta.src_ip_address: exact @name("ip_address");
        }
        actions = {
            ignore_src;
            match_src_device;
            match_src_device_limit;
            @defaultonly deny;
        }
        size = 512;
        default_action = deny();
    }

    action ignore_dst(bit<32> id, bit<32> sub_id, bit<16> manufacturer_id, bit<16> model_id) {
        meta.valid_dst = false;
        meta.dst_id = id;
        meta.dst_sub_id = sub_id;
        meta.dst_manufacturer_id = manufacturer_id;
        meta.dst_model_id = model_id;
    }

    action match_dst_device(bit<32> id, bit<32> sub_id, bit<16> manufacturer_id, bit<16> model_id) {
        meta.valid_dst = true;
        meta.dst_id = id;
        meta.dst_sub_id = sub_id;
        meta.dst_manufacturer_id = manufacturer_id;
        meta.dst_model_id = model_id;
    }

    action match_dst_device_limit(bit<10> meter_id, bit<32> id, bit<32> sub_id, bit<16> manufacturer_id, bit<16> model_id) {
        meta.valid_dst = true;
        meta.dst_id = id;
        meta.dst_sub_id = sub_id;
        meta.dst_manufacturer_id = manufacturer_id;
        meta.dst_model_id = model_id;

        use_dst_meter = 1;
        dst_meter_id = meter_id;
    }

    action match_dst_ip() {
        use_dst_ip = 1;
    }

    table device_dst_mac {
        key = {
            headers.ethernet.dst_address: exact @name("mac_address");
        }
        actions = {
            ignore_dst;
            match_dst_device;
            match_dst_device_limit;
            @defaultonly match_dst_ip;
        }
        size = 256;
        default_action = match_dst_ip();
    }

    table device_dst_ip {
        key = {
            meta.dst_ip_address: exact @name("ip_address");
        }
        actions = {
            ignore_dst;
            match_dst_device;
            match_dst_device_limit;
            @defaultonly deny;
        }
        size = 256;
        default_action = deny();
    }

    apply {
        // Validate Source Device
        device_src.apply();
            
        // Check meter

        // Validate Destination Device
        device_dst_mac.apply();
        if (use_dst_ip == 1) {
            device_dst_ip.apply();
        }

        
    
        // Check meter
        if (src_meter_tag == MeterColor_t.RED) {
            deny();
        }
        else if (use_dst_meter == 1) {
            if (dst_traffic_meter.execute(dst_meter_id) == MeterColor_t.RED) {
                deny();
            }
        }
    }
}

#endif /* __ACL__ */
