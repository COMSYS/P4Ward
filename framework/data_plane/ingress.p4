/* -*- P4_16 -*- */
#ifndef __INGRESS__
#define __INGRESS__

#include <core.p4>
#include <tna.p4>

#include "types.p4"

#include "headers/ethernet.p4"
#include "headers/ipv4.p4"
#include "headers/ipv6.p4"
#include "headers/arp.p4"
#include "headers/tcp.p4"
#include "headers/udp.p4"
#include "headers/eap.p4"
#include "headers/enip.p4"

#include "controls/arp.p4"

#include "controls/auth.p4"

#include "controls/device_validator.p4"
#include "controls/acl.p4"

#include "controls/routing.p4"

parser IngressParser(
    packet_in packet,
    out ingress_headers_t headers,
    out ingress_metadata_t meta,
    out ingress_intrinsic_metadata_t intr_meta) {

    state start {
        packet.extract(intr_meta);
        packet.advance(PORT_METADATA_SIZE);

        meta.port = 9w0;

        meta.payload_length = 0;

        meta.protocol_flags = 32w0;
        meta.src_ip_address = 128w0;
        meta.dst_ip_address = 128w0;
        meta.src_port = 16w0;
        meta.dst_port = 16w0;

        meta.from_protocol_id =  VALIDATOR_NO_PROTOCOL;
        meta.to_protocol_id =  VALIDATOR_NO_PROTOCOL;

        transition select(intr_meta.ingress_port) {
            68: parse_recirculation;
            196: parse_recirculation;
            default: parse_normal;
        }
    }

    state parse_normal {
        meta.port = intr_meta.ingress_port;

        transition parse_ethernet;
    }

    state parse_recirculation {
        packet.extract(headers.recirculation);

        meta.port = headers.recirculation.port;

        transition parse_ethernet;
    }

    /*        Layer 2        */

    state parse_ethernet {
        packet.extract(headers.ethernet);
        meta.protocol_flags = meta.protocol_flags | protocol_id_t.ETHERNET;

        transition select(headers.ethernet.ether_type) {
            ether_type_t.IPV4: parse_ipv4;
            ether_type_t.ARP: parse_arp;
            ether_type_t.IPV6: parse_ipv6;
            ether_type_t.VLAN: parse_vlan;
            ether_type_t.EAPOL: parse_eapol;
            ether_type_t.GOOSE: parse_goose; // Goose will only be parsed in the egress stage
#ifndef DISABLE_MONITORING
            ether_type_t.MONITORING: parse_monitoring;
#endif
            default: reject;
        }
    }

#ifndef DISABLE_MONITORING
    state parse_monitoring {
        packet.extract(headers.monitoring);

        transition select(headers.monitoring.ether_type) {
            ether_type_t.IPV4: parse_ipv4;
            ether_type_t.ARP: parse_arp;
            ether_type_t.IPV6: parse_ipv6;
            ether_type_t.VLAN: parse_vlan;
            ether_type_t.EAPOL: parse_eapol;
            ether_type_t.GOOSE: parse_goose; // Goose will only be parsed in the egress stage
            default: reject;
        }
    }
#endif

    state parse_vlan {
        packet.extract(headers.vlan);
        meta.protocol_flags = meta.protocol_flags | protocol_id_t.VLAN;

        transition select(headers.vlan.ether_type) {
            ether_type_t.IPV4: parse_ipv4;
            ether_type_t.ARP: parse_arp;
            ether_type_t.IPV6: parse_ipv6;
            ether_type_t.EAPOL: parse_eapol;
            ether_type_t.GOOSE: parse_goose; // Goose will only be parsed in the egress stage
            default: reject;
        }
    }

    /*        Layer 3        */

    state parse_ipv4 {
        packet.extract(headers.ipv4);
        meta.protocol_flags = meta.protocol_flags | protocol_id_t.IPV4;

        meta.src_ip_address = (bit<128>)headers.ipv4.src_address;
        meta.src_ip_address = meta.src_ip_address | IPV4_TO_IPV6;
        meta.dst_ip_address = (bit<128>)headers.ipv4.dst_address;
        meta.dst_ip_address = meta.dst_ip_address | IPV4_TO_IPV6;

        transition select(headers.ipv4.protocol) {
            ipv4_protocol_t.ICMP: parse_icmp;
            ipv4_protocol_t.TCP: parse_tcp;
            ipv4_protocol_t.UDP: parse_udp;
            default: reject;
        }
    }

    state parse_arp {
        packet.extract(headers.arp);
        meta.protocol_flags = meta.protocol_flags | protocol_id_t.ARP;
        meta.payload_length = 0x1; // Workaround the zero payload issue

        transition accept;
    }

    state parse_ipv6 {
        packet.extract(headers.ipv6);
        meta.protocol_flags = meta.protocol_flags | protocol_id_t.IPV6;

        meta.src_ip_address = headers.ipv6.src_address;
        meta.dst_ip_address = headers.ipv6.dst_address;

        transition select(headers.ipv6.next_header) {
            ipv6_protocol_t.ICMP: parse_icmp;
            ipv6_protocol_t.TCP: parse_tcp;
            ipv6_protocol_t.UDP: parse_udp;
            default: reject;
        }
    }

    state parse_icmp {
        packet.extract(headers.icmp);
        meta.protocol_flags = meta.protocol_flags | protocol_id_t.ICMP;

        transition accept;
    }

    state parse_eapol {
        packet.extract(headers.eapol);
        
        transition select(headers.eapol.version, headers.eapol.type){
            (eapol_version_t.VERSION_1, eapol_type_t.EAP_PACKET): parse_eap;
            (eapol_version_t.VERSION_1, eapol_type_t.START): parse_eap;
            (eapol_version_t.VERSION_1, eapol_type_t.LOGOFF): parse_eap;
            default: reject;
        }
    }

    state parse_eap {
        packet.extract(headers.eap);

        transition select(headers.eap.code){
            eap_code_t.REQUEST: accept;
            eap_code_t.RESPONSE: parse_eap_msg;
            eap_code_t.SUCCESS: accept;
            eap_code_t.FAILURE: accept;
            default: reject;
        }
    }

    state parse_eap_msg {
        packet.extract(headers.eap_msg);

        transition select(headers.eap_msg.type){
            eap_msg_type_t.MD5: parse_eap_md5;
            eap_msg_type_t.OTP: parse_eap_otp;
            default: reject;
        }
    }

    state parse_eap_md5 {
        packet.extract(headers.eap_md5);
        transition accept;
    }

    state parse_eap_otp {
        packet.extract(headers.eap_otp);
        transition accept;
    }

    state parse_goose {
        meta.protocol_flags = meta.protocol_flags | protocol_id_t.GOOSE;
        meta.payload_length = 0x1; // Workaround the zero payload issue

        transition accept;
    }

    /*        Layer 4        */

    state parse_tcp {
        packet.extract(headers.tcp);
        meta.protocol_flags = meta.protocol_flags | protocol_id_t.TCP;

        meta.src_port = headers.tcp.src_port;
        meta.dst_port = headers.tcp.dst_port;

        transition select(headers.tcp.data_offset) {
            5: parse_tcp_option_00;
            6: parse_tcp_option_01;
            7: parse_tcp_option_02;
            8: parse_tcp_option_03;
            9: parse_tcp_option_04;
            10: parse_tcp_option_05;
            11: parse_tcp_option_06;
            12: parse_tcp_option_07;
            13: parse_tcp_option_08;
            14: parse_tcp_option_09;
            15: parse_tcp_option_10;
            default: reject;
        }
    }

    state parse_tcp_option_00 {
        meta.payload_length = -TCP_HEADER_SIZE;

        transition accept;
    }

    state parse_tcp_option_01 {
        packet.extract(headers.tcp_option_01);

        meta.payload_length = -(TCP_HEADER_SIZE + 4);

        transition accept;
    }

    state parse_tcp_option_02 {
        packet.extract(headers.tcp_option_01);
        packet.extract(headers.tcp_option_02);

        meta.payload_length = -(TCP_HEADER_SIZE + 8);

        transition accept;
    }

    state parse_tcp_option_03 {
        packet.extract(headers.tcp_option_01);
        packet.extract(headers.tcp_option_02);
        packet.extract(headers.tcp_option_03);

        meta.payload_length = -(TCP_HEADER_SIZE + 12);

        transition accept;
    }

    state parse_tcp_option_04 {
        packet.extract(headers.tcp_option_01);
        packet.extract(headers.tcp_option_02);
        packet.extract(headers.tcp_option_03);
        packet.extract(headers.tcp_option_04);

        meta.payload_length = -(TCP_HEADER_SIZE + 16);

        transition accept;
    }

    state parse_tcp_option_05 {
        packet.extract(headers.tcp_option_01);
        packet.extract(headers.tcp_option_02);
        packet.extract(headers.tcp_option_03);
        packet.extract(headers.tcp_option_04);
        packet.extract(headers.tcp_option_05);

        meta.payload_length = -(TCP_HEADER_SIZE + 20);

        transition accept;
    }

    state parse_tcp_option_06 {
        packet.extract(headers.tcp_option_01);
        packet.extract(headers.tcp_option_02);
        packet.extract(headers.tcp_option_03);
        packet.extract(headers.tcp_option_04);
        packet.extract(headers.tcp_option_05);
        packet.extract(headers.tcp_option_06);

        meta.payload_length = -(TCP_HEADER_SIZE + 24);

        transition accept;
    }

    state parse_tcp_option_07 {
        packet.extract(headers.tcp_option_01);
        packet.extract(headers.tcp_option_02);
        packet.extract(headers.tcp_option_03);
        packet.extract(headers.tcp_option_04);
        packet.extract(headers.tcp_option_05);
        packet.extract(headers.tcp_option_06);
        packet.extract(headers.tcp_option_07);

        meta.payload_length = -(TCP_HEADER_SIZE + 28);

        transition accept;
    }

    state parse_tcp_option_08 {
        packet.extract(headers.tcp_option_01);
        packet.extract(headers.tcp_option_02);
        packet.extract(headers.tcp_option_03);
        packet.extract(headers.tcp_option_04);
        packet.extract(headers.tcp_option_05);
        packet.extract(headers.tcp_option_06);
        packet.extract(headers.tcp_option_07);
        packet.extract(headers.tcp_option_08);

        meta.payload_length = -(TCP_HEADER_SIZE + 32);

        transition accept;
    }

    state parse_tcp_option_09 {
        packet.extract(headers.tcp_option_01);
        packet.extract(headers.tcp_option_02);
        packet.extract(headers.tcp_option_03);
        packet.extract(headers.tcp_option_04);
        packet.extract(headers.tcp_option_05);
        packet.extract(headers.tcp_option_06);
        packet.extract(headers.tcp_option_07);
        packet.extract(headers.tcp_option_08);
        packet.extract(headers.tcp_option_09);

        meta.payload_length = -(TCP_HEADER_SIZE + 36);

        transition accept;
    }

    state parse_tcp_option_10 {
        packet.extract(headers.tcp_option_01);
        packet.extract(headers.tcp_option_02);
        packet.extract(headers.tcp_option_03);
        packet.extract(headers.tcp_option_04);
        packet.extract(headers.tcp_option_05);
        packet.extract(headers.tcp_option_06);
        packet.extract(headers.tcp_option_07);
        packet.extract(headers.tcp_option_08);
        packet.extract(headers.tcp_option_09);
        packet.extract(headers.tcp_option_10);

        meta.payload_length = -(TCP_HEADER_SIZE + 40);

        transition accept;
    }
    
    state parse_udp {
        packet.extract(headers.udp);
        meta.protocol_flags = meta.protocol_flags | protocol_id_t.UDP;
        meta.payload_length = meta.payload_length | (-UDP_HEADER_SIZE);

        meta.src_port = headers.udp.src_port;
        meta.dst_port = headers.udp.dst_port;

        transition accept;
    }
}

control Ingress(
    inout ingress_headers_t headers,
    inout ingress_metadata_t meta,
    in ingress_intrinsic_metadata_t intr_meta,
    in ingress_intrinsic_metadata_from_parser_t parser_meta,
    inout ingress_intrinsic_metadata_for_deparser_t deparser_meta,
    inout ingress_intrinsic_metadata_for_tm_t traffic_manager_meta)
{
    ArpControl() arp;
    
    AuthControl() auth;
    
    DeviceValidatorControl() device_validator;
    AclControl() acl;

    RoutingControl() routing;

    apply {
        traffic_manager_meta.copy_to_cpu = 0;

#ifndef DISABLE_MONITORING
        if (headers.recirculation.isValid()) {
            headers.monitoring.in_timestamp_recirculation = parser_meta.global_tstamp;
        }
        else {
            headers.monitoring.in_timestamp = parser_meta.global_tstamp;
        }
#endif

        routing.apply(headers, meta, intr_meta, parser_meta, deparser_meta, traffic_manager_meta);

        bit<16> l3_payload_length = 0;
        if (headers.ipv4.isValid()) {
            l3_payload_length = headers.ipv4.total_length - IPV4_HEADER_SIZE;
        }
        else if (headers.ipv6.isValid()) {
            l3_payload_length = headers.ipv6.payload_length;
        }
        meta.payload_length = meta.payload_length + l3_payload_length;

        if(meta.port != CPU_PORT) {
            if (headers.eap.isValid()) {
                auth.apply(headers, meta, intr_meta, parser_meta, deparser_meta, traffic_manager_meta);
            }
            else {
                if (meta.src_network_id != meta.dst_network_id) {
                    deparser_meta.drop_ctl = 1;
                    exit;
                }

                if (headers.arp.isValid()) {
                    arp.apply(headers, meta, intr_meta, parser_meta, deparser_meta, traffic_manager_meta);
                }
                device_validator.apply(headers, meta, intr_meta, parser_meta, deparser_meta, traffic_manager_meta);
                acl.apply(headers, meta, intr_meta, parser_meta, deparser_meta, traffic_manager_meta);
            }
        }

        // Always block recirculation
        // Recirculations have to immediately exit
        headers.recirculation.setInvalid();
        
        // Set egress metadata
        headers.egress_meta.setValid();

#ifndef DISABLE_MONITORING
        headers.egress_meta.ingress_port = meta.port;
#endif

        headers.egress_meta.payload_length = meta.payload_length;

        headers.egress_meta.ace_from_id = meta.ace_from_id;
        headers.egress_meta.ace_to_id = meta.ace_to_id;
        
        headers.egress_meta.from_protocol_id = meta.from_protocol_id;
        headers.egress_meta.to_protocol_id = meta.to_protocol_id;
        
        headers.egress_meta.validator_flags = meta.validator_flags;
        headers.egress_meta.protocol_validator_flags = meta.protocol_validator_flags;
    }
}

control IngressDeparser(
    packet_out packet,
    inout ingress_headers_t headers,
    in ingress_metadata_t meta,
    in ingress_intrinsic_metadata_for_deparser_t intr_meta)
{
    Checksum() ipv4_checksum;

    apply {

        if (headers.ipv4.isValid()) {
            headers.ipv4.checksum = ipv4_checksum.update({
                headers.ipv4.version,
                headers.ipv4.ihl,
                headers.ipv4.tos,
                headers.ipv4.total_length,
                headers.ipv4.identification,
                headers.ipv4.flags,
                headers.ipv4.fragment_offset,
                headers.ipv4.ttl,
                headers.ipv4.protocol,
                headers.ipv4.src_address,
                headers.ipv4.dst_address
            });
        }

        packet.emit(headers);
    }
}

#endif