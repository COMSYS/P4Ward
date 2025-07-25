/* -*- P4_16 -*- */
#ifndef __CONTROLS_ARP__
#define __CONTROLS_ARP__

#include <core.p4>
#include <tna.p4>

#include "../types.p4"

control ArpControl(
    inout ingress_headers_t headers,
    inout ingress_metadata_t meta,
    in ingress_intrinsic_metadata_t intr_meta,
    in ingress_intrinsic_metadata_from_parser_t parser_meta,
    inout ingress_intrinsic_metadata_for_deparser_t deparser_meta,
    inout ingress_intrinsic_metadata_for_tm_t traffic_manager_meta) {

    action arp_reply(MacAddress_t device_mac_address) {
        Ipv4Address_t device_ip_address = headers.arp.dst_ip;

        headers.arp.dst_mac = headers.arp.src_mac;
        headers.arp.dst_ip = headers.arp.src_ip;
        headers.arp.src_mac = device_mac_address;
        headers.arp.src_ip = device_ip_address;
        headers.arp.opcode = arp_opcode_t.REPLY;

        headers.ethernet.dst_address = headers.arp.dst_mac;
        headers.ethernet.src_address = headers.arp.src_mac;

        traffic_manager_meta.ucast_egress_port = intr_meta.ingress_port;
        traffic_manager_meta.bypass_egress = 1;
        exit;
    }

    table arp_replies {
        key = {
            meta.port: exact @name("port");
            headers.arp.dst_ip: exact @name("ip_address");
        }
        actions = {
            arp_reply;
            @defaultonly NoAction;
        }
        size = 512;
        default_action = NoAction();
    }

    apply {
        if (headers.arp.opcode == arp_opcode_t.REQUEST) {
            arp_replies.apply();
        }
    }
}

#endif
