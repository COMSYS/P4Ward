/* -*- P4_16 -*- */
#ifndef __EGRESS__
#define __EGRESS__

#include <core.p4>
#include <tna.p4>

#include "types.p4"

#include "controls/validator/arp_validator.p4"
#include "controls/validator/icmp_validator.p4"
#include "controls/validator/enip_validator.p4"
#include "controls/validator/modbus_validator.p4"
#include "controls/validator/opcua_validator.p4"
#include "controls/validator/goose_validator.p4"

parser EgressParser(
    packet_in packet,
    out egress_headers_t headers,
    out egress_metadata_t meta,
    out egress_intrinsic_metadata_t intr_meta)
{
    state start {

        packet.extract(intr_meta);
        packet.extract(headers.egress_meta);
        
        meta.from_protocol_id = headers.egress_meta.from_protocol_id;
        meta.to_protocol_id = headers.egress_meta.to_protocol_id;

        meta.validator_mask = 0;
        meta.protocol_validator_mask = 0;

        transition select(headers.egress_meta.payload_length) {
            0: without_payload;
            default: parse_ethernet;
        }
    }

    state without_payload {
        // meta.from_protocol_id = meta.from_protocol_id & VALIDATOR_NO_PROTOCOL;
        // meta.to_protocol_id = meta.to_protocol_id & VALIDATOR_NO_PROTOCOL;

        // transition parse_ethernet;
        transition accept;
    }

    /*        Layer 2        */

    state parse_ethernet {
        packet.extract(headers.ethernet);

        transition select(headers.ethernet.ether_type) {
            ether_type_t.IPV4: parse_ipv4;
            ether_type_t.ARP: accept;
            ether_type_t.IPV6: parse_ipv6;
            ether_type_t.VLAN: parse_vlan;
            ether_type_t.EAPOL: accept;
            ether_type_t.GOOSE: parse_goose;
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
            ether_type_t.ARP: accept;
            ether_type_t.IPV6: parse_ipv6;
            ether_type_t.VLAN: parse_vlan;
            ether_type_t.EAPOL: accept;
            ether_type_t.GOOSE: parse_goose;
            default: reject;
        }
    }
#endif

    state parse_vlan {
        packet.extract(headers.vlan);

        transition select(headers.vlan.ether_type) {
            ether_type_t.IPV4: parse_ipv4;
            ether_type_t.ARP: parse_arp;
            ether_type_t.IPV6: parse_ipv6;
            ether_type_t.EAPOL: accept;
            ether_type_t.GOOSE: parse_goose;
            default: reject;
        }
    }

    /*        Layer 3        */

    state parse_ipv4 {
        packet.extract(headers.ipv4);
        
        transition select(headers.ipv4.protocol) {
            ipv4_protocol_t.ICMP: parse_icmp;
            ipv4_protocol_t.TCP: parse_tcp;
            ipv4_protocol_t.UDP: parse_udp;
            default: reject;
        }
    }

    state parse_arp {
        packet.extract(headers.arp);

        transition accept;
    }

    state parse_ipv6 {
        packet.extract(headers.ipv6);

        transition select(headers.ipv6.next_header) {
            ipv6_protocol_t.ICMP: parse_icmp;
            ipv6_protocol_t.TCP: parse_tcp;
            ipv6_protocol_t.UDP: parse_udp;
            default: reject;
        }
    }

    state parse_icmp {
        packet.extract(headers.icmp);

        transition accept;
    }

    /*        Layer 4        */

    state parse_tcp {
        packet.extract(headers.tcp);
        
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

    state parse_tcp_options {
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
        transition parse_tcp_no_options;
    }

    state parse_tcp_option_01 {
        packet.extract(headers.tcp_option_01);

        transition parse_tcp_no_options;
    }

    state parse_tcp_option_02 {
        packet.extract(headers.tcp_option_01);
        packet.extract(headers.tcp_option_02);

        transition parse_tcp_no_options;
    }

    state parse_tcp_option_03 {
        packet.extract(headers.tcp_option_01);
        packet.extract(headers.tcp_option_02);
        packet.extract(headers.tcp_option_03);

        transition parse_tcp_no_options;
    }

    state parse_tcp_option_04 {
        packet.extract(headers.tcp_option_01);
        packet.extract(headers.tcp_option_02);
        packet.extract(headers.tcp_option_03);
        packet.extract(headers.tcp_option_04);

        transition parse_tcp_no_options;
    }

    state parse_tcp_option_05 {
        packet.extract(headers.tcp_option_01);
        packet.extract(headers.tcp_option_02);
        packet.extract(headers.tcp_option_03);
        packet.extract(headers.tcp_option_04);
        packet.extract(headers.tcp_option_05);

        transition parse_tcp_no_options;
    }

    state parse_tcp_option_06 {
        packet.extract(headers.tcp_option_01);
        packet.extract(headers.tcp_option_02);
        packet.extract(headers.tcp_option_03);
        packet.extract(headers.tcp_option_04);
        packet.extract(headers.tcp_option_05);
        packet.extract(headers.tcp_option_06);

        transition parse_tcp_no_options;
    }

    state parse_tcp_option_07 {
        packet.extract(headers.tcp_option_01);
        packet.extract(headers.tcp_option_02);
        packet.extract(headers.tcp_option_03);
        packet.extract(headers.tcp_option_04);
        packet.extract(headers.tcp_option_05);
        packet.extract(headers.tcp_option_06);
        packet.extract(headers.tcp_option_07);

        transition parse_tcp_no_options;
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

        transition parse_tcp_no_options;
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

        transition parse_tcp_no_options;
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

        transition parse_tcp_no_options;
    }

    state parse_tcp_no_options {

        transition select(headers.egress_meta.from_protocol_id, headers.egress_meta.to_protocol_id) {
            ( VALIDATOR_NO_PROTOCOL,  VALIDATOR_NO_PROTOCOL): accept; // Both sides don't impose any verifications

            ( VALIDATOR_UNDEFINED,  VALIDATOR_UNDEFINED): accept;
            ( VALIDATOR_NO_PROTOCOL,  VALIDATOR_UNDEFINED): accept;
            ( VALIDATOR_UNDEFINED,  VALIDATOR_NO_PROTOCOL): accept;

            ( VALIDATOR_ENIP,  VALIDATOR_ENIP): parse_enip;
            ( VALIDATOR_ENIP,  VALIDATOR_NO_PROTOCOL): parse_enip;
            ( VALIDATOR_NO_PROTOCOL,  VALIDATOR_ENIP): parse_enip;

            ( VALIDATOR_MODBUS,  VALIDATOR_MODBUS): parse_modbus;
            ( VALIDATOR_MODBUS,  VALIDATOR_NO_PROTOCOL): parse_modbus;
            ( VALIDATOR_NO_PROTOCOL,  VALIDATOR_MODBUS): parse_modbus;

            ( VALIDATOR_OPCUA,  VALIDATOR_OPCUA): parse_opcua;
            ( VALIDATOR_OPCUA,  VALIDATOR_NO_PROTOCOL): parse_opcua;
            ( VALIDATOR_NO_PROTOCOL,  VALIDATOR_OPCUA): parse_opcua;

            default: reject; // Verifications don't match up which is not allowed
        }
    }

    state parse_udp {
        packet.extract(headers.udp);
        
        transition select(headers.egress_meta.from_protocol_id, headers.egress_meta.to_protocol_id) {
            ( VALIDATOR_NO_PROTOCOL,  VALIDATOR_NO_PROTOCOL): accept; // Both sides don't impose any verifications

            ( VALIDATOR_UNDEFINED,  VALIDATOR_UNDEFINED): accept;
            ( VALIDATOR_NO_PROTOCOL,  VALIDATOR_UNDEFINED): accept;
            ( VALIDATOR_UNDEFINED,  VALIDATOR_NO_PROTOCOL): accept;

            ( VALIDATOR_ENIP,  VALIDATOR_ENIP): parse_enip;
            ( VALIDATOR_ENIP,  VALIDATOR_NO_PROTOCOL): parse_enip;
            ( VALIDATOR_NO_PROTOCOL,  VALIDATOR_ENIP): parse_enip;

            default: reject; // Verifications don't match up which is not allowed
        }
    }

    /* Layer 7 */

    /************* ENIP *************/
    state parse_enip {
        packet.extract(headers.enip);

        transition accept;
    }

    /************* MODBUS *************/
    state parse_modbus {
        packet.extract(headers.modbus);

        transition select(headers.modbus.protocol_id) {
            0: parse_modbus_2;
            default: reject;
        }
    }

    state parse_modbus_2 {
        transition select(headers.modbus.function_code[7:7]) {
            0: accept;
            1: parse_modbus_exception;
        }
    }

    state parse_modbus_exception {
        packet.extract(headers.modbus_exception);

        transition accept;
    }

    /************* OPCUA *************/
    state parse_opcua {
        packet.extract(headers.opcua);

        transition select(headers.opcua.message_type) {
            opcua_message_type_t.OPN: parse_opcua_open;
            opcua_message_type_t.ERR: parse_opcua_error;
            opcua_message_type_t.MSG: accept;
            opcua_message_type_t.CLO: accept;
            opcua_message_type_t.HEL: accept;
            opcua_message_type_t.ACK: accept;
            opcua_message_type_t.RHE: accept;
            default: reject;
        }
    }

    state parse_opcua_open {
        packet.extract(headers.opcua_asymmetric_algorithm);

        transition select(headers.opcua_asymmetric_algorithm.security_policy_uri_length.part_4) {
            64: parse_opcua_policy_aes128_sha256_rsa0aep;   // http://opcfoundation.org/UA/SecurityPolicy#Aes128_Sha256_RsaOaep
            63: parse_opcua_policy_aes256_sha256_rsapss;    // http://opcfoundation.org/UA/SecurityPolicy#Aes256_Sha256_RsaPss
            56: parse_opcua_policy_basic128rsa15;           // http://opcfoundation.org/UA/SecurityPolicy#Basic128Rsa15
            51: parse_opcua_policy_basic256;                // http://opcfoundation.org/UA/SecurityPolicy#Basic256
            57: parse_opcua_policy_basic256sha256;          // http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256
            47: parse_opcua_policy_none;                    // http://opcfoundation.org/UA/SecurityPolicy#None
            default: reject;
        }
    }

    state parse_opcua_policy_aes128_sha256_rsa0aep {
        packet.extract(headers.opcua_security_policy_uri_1);
        packet.extract(headers.opcua_security_policy_uri_2);
        packet.extract(headers.opcua_security_policy_uri_3);
        packet.extract(headers.opcua_security_policy_uri_4);
        packet.extract(headers.opcua_security_policy_uri_5);
        packet.extract(headers.opcua_security_policy_uri_6);
        packet.extract(headers.opcua_security_policy_uri_7);

        transition accept;
    }

    state parse_opcua_policy_aes256_sha256_rsapss {
        packet.extract(headers.opcua_security_policy_uri_1);
        packet.extract(headers.opcua_security_policy_uri_2);
        packet.extract(headers.opcua_security_policy_uri_3);
        packet.extract(headers.opcua_security_policy_uri_4);
        packet.extract(headers.opcua_security_policy_uri_5);
        packet.extract(headers.opcua_security_policy_uri_6);
        headers.opcua_security_policy_uri_7.security_policy_uri = 0;

        transition accept;
    }

    state parse_opcua_policy_basic128rsa15 {
        packet.extract(headers.opcua_security_policy_uri_1);
        packet.extract(headers.opcua_security_policy_uri_2);
        packet.extract(headers.opcua_security_policy_uri_3);
        packet.extract(headers.opcua_security_policy_uri_4);
        headers.opcua_security_policy_uri_5.security_policy_uri = 0;
        headers.opcua_security_policy_uri_6.security_policy_uri = 0;
        headers.opcua_security_policy_uri_7.security_policy_uri = 0;

        transition accept;
    }

    state parse_opcua_policy_basic256 {
        packet.extract(headers.opcua_security_policy_uri_1);
        packet.extract(headers.opcua_security_policy_uri_2);
        packet.extract(headers.opcua_security_policy_uri_3);
        headers.opcua_security_policy_uri_4.security_policy_uri = 0;
        headers.opcua_security_policy_uri_5.security_policy_uri = 0;
        headers.opcua_security_policy_uri_6.security_policy_uri = 0;
        headers.opcua_security_policy_uri_7.security_policy_uri = 0;

        transition accept;
    }

    state parse_opcua_policy_basic256sha256 {
        packet.extract(headers.opcua_security_policy_uri_1);
        packet.extract(headers.opcua_security_policy_uri_2);
        packet.extract(headers.opcua_security_policy_uri_3);
        packet.extract(headers.opcua_security_policy_uri_4);
        packet.extract(headers.opcua_security_policy_uri_5);
        headers.opcua_security_policy_uri_6.security_policy_uri = 0;
        headers.opcua_security_policy_uri_7.security_policy_uri = 0;

        transition accept;
    }

    state parse_opcua_policy_none {
        packet.extract(headers.opcua_security_policy_uri_1);
        packet.extract(headers.opcua_security_policy_uri_2);
        headers.opcua_security_policy_uri_3.security_policy_uri = 0;
        headers.opcua_security_policy_uri_4.security_policy_uri = 0;
        headers.opcua_security_policy_uri_5.security_policy_uri = 0;
        headers.opcua_security_policy_uri_6.security_policy_uri = 0;
        headers.opcua_security_policy_uri_7.security_policy_uri = 0;

        transition accept;
    }

    state parse_opcua_error {
        packet.extract(headers.opcua_error);

        transition accept;
    }

    /************* GOOSE *************/

    state parse_goose {
        transition select(headers.egress_meta.from_protocol_id, headers.egress_meta.to_protocol_id) {
            (VALIDATOR_NO_PROTOCOL,  VALIDATOR_NO_PROTOCOL): accept; // Both sides don't impose any verifications

            (VALIDATOR_GOOSE,  VALIDATOR_GOOSE): parse_goose_2;
            (VALIDATOR_GOOSE,  VALIDATOR_NO_PROTOCOL): parse_goose_2;
            (VALIDATOR_NO_PROTOCOL,  VALIDATOR_GOOSE): parse_goose_2;

            default: reject; // Verifications don't match up which is not allowed
        }
    }

    state parse_goose_2 {
        packet.extract(headers.goose);

        transition accept;
    }
}

control Egress(
    inout egress_headers_t headers,
    inout egress_metadata_t meta,
    in egress_intrinsic_metadata_t intr_meta,
    in egress_intrinsic_metadata_from_parser_t parser_meta,
    inout egress_intrinsic_metadata_for_deparser_t deparser_meta,
    inout egress_intrinsic_metadata_for_output_port_t output_port_meta)
{
    ArpValidatorControl() arp_validator;
    IcmpValidatorControl() icmp_validator;
    EnipValidatorControl() enip_validator;
    ModBusValidatorControl() modbus_validator;
    OPCUAValidatorControl() opcua_validator;
    GOOSEValidatorControl() goose_validator;

    apply {
#ifndef DISABLE_MONITORING
        if (headers.monitoring.isValid()) {
            headers.monitoring.out_timestamp = parser_meta.global_tstamp;

            if (intr_meta.egress_port == CPU_PORT) {
                headers.monitoring.setInvalid();
            }
        }
#endif

        if (headers.arp.isValid()) {
            arp_validator.apply(headers, meta, intr_meta, parser_meta, deparser_meta, output_port_meta);
        }
        else if (headers.icmp.isValid()) {
            icmp_validator.apply(headers, meta, intr_meta, parser_meta, deparser_meta, output_port_meta);
        }
        else if (headers.enip.isValid()) {
            enip_validator.apply(headers, meta, intr_meta, parser_meta, deparser_meta, output_port_meta);
        } 
        else if(headers.modbus.isValid()) {
            modbus_validator.apply(headers, meta, intr_meta, parser_meta, deparser_meta, output_port_meta);
        }
        else if(headers.opcua.isValid()) {
            opcua_validator.apply(headers, meta, intr_meta, parser_meta, deparser_meta, output_port_meta);
        }
        else if(headers.goose.isValid()) {
            goose_validator.apply(headers, meta, intr_meta, parser_meta, deparser_meta, output_port_meta);
        }
        
        headers.egress_meta.setInvalid();
        headers.egress_meta.validator_flags = headers.egress_meta.validator_flags & meta.validator_mask;
        headers.egress_meta.protocol_validator_flags = headers.egress_meta.protocol_validator_flags & meta.protocol_validator_mask;

#ifndef DISABLE_MONITORING
        headers.monitoring.out_timestamp = parser_meta.global_tstamp;
#endif
        
        bit<16> flags = headers.egress_meta.validator_flags ++ headers.egress_meta.protocol_validator_flags;
        if (flags != 0x00) {
            deparser_meta.drop_ctl = 1;
            exit;
        }
    }
}

control EgressDeparser(
    packet_out packet,
    inout egress_headers_t headers,
    in egress_metadata_t meta,
    in egress_intrinsic_metadata_for_deparser_t intr_meta)
{
    apply {
        packet.emit(headers);
    }
}

#endif