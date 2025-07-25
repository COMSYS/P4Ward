/* -*- P4_16 -*- */
#ifndef __TYPES__
#define __TYPES__

#include <core.p4>
#include <tna.p4>

#include "headers/ethernet.p4"

#ifndef DISABLE_MONITORING
#include "headers/monitoring.p4"
#endif

#include "headers/ipv4.p4"
#include "headers/arp.p4"
#include "headers/ipv6.p4"
#include "headers/icmp.p4"
#include "headers/eap.p4"

#include "headers/tcp.p4"
#include "headers/udp.p4"

#include "headers/enip.p4"
#include "headers/modbus.p4"
#include "headers/opcua.p4"
#include "headers/goose.p4"

const PortId_t CPU_PORT = 192;

// Only the LEAST significant bits are used to recirculate
// The two MOST significat bits are used to differentiate 
// between the two pipeline of the tofino switch
const bit<7> RECIRCULATION_PORT = 68;

header recirculation_h {
    @padding bit<(8 - PORT_ID_WIDTH % 8)> _pad1;
    PortId_t port;
}

typedef bit<4> protocol_validator_id_t;
const bit<4> VALIDATOR_NO_PROTOCOL = 0;
const bit<4> VALIDATOR_UNDEFINED = 1;
const bit<4> VALIDATOR_ENIP = 2;
const bit<4> VALIDATOR_MODBUS = 3;
const bit<4> VALIDATOR_OPCUA = 4;
const bit<4> VALIDATOR_GOOSE = 5;

// Flags
const bit<8> VALIDATOR_FLAG_NONE = 0x00;
const bit<8> VALIDATOR_FLAG_IS_NOT_CLIENT = 0x01;
const bit<8> VALIDATOR_FLAG_IS_NOT_SERVER = 0x02;
const bit<8> VALIDATOR_FLAG_DISABLE_WRITE = 0x04;
const bit<8> VALIDATOR_FLAG_DISABLE_REQUEST = 0x08;
const bit<8> VALIDATOR_FLAG_DISABLE_REPLY = 0x10;

header egress_in_metadata_h {
#ifndef DISABLE_MONITORING
    @padding bit<(8 - PORT_ID_WIDTH % 8)> _pad1;
    PortId_t ingress_port;
#endif

    bit<16> payload_length;

    bit<16> ace_from_id;
    bit<16> ace_to_id;

    protocol_validator_id_t from_protocol_id;
    protocol_validator_id_t to_protocol_id;

    // Flag meaning:
    // 8: Unused
    // 7: Unused
    // 6: Unused
    // 5: Unused
    // 4: Unused
    // 3: Disable Write
    // 2: Is NOT Server
    // 1: Is NOT Client
    bit<8> validator_flags;
    bit<8> protocol_validator_flags;
}

struct ingress_headers_t {
    /* -------- Metadata -------- */
    recirculation_h recirculation;
    egress_in_metadata_h egress_meta;

    /* -------- Layer 2 -------- */
    ethernet_h ethernet;
    monitoring_h monitoring;
    vlan_h vlan;

    /* -------- Metadata -------- */
    eap_metadata_h eap_metadata;

    /* -------- Layer 3 -------- */
    ipv4_h ipv4;
    ipv6_h ipv6;

    arp_h arp;
    icmp_h icmp;

    eapol_h eapol;
    eap_h eap;
    eap_msg_h eap_msg;

    eap_md5_h eap_md5;

    eap_otp_h eap_otp;

    /* -------- Layer 4 -------- */
    tcp_h tcp;
    tcp_option_word_h tcp_option_01;
    tcp_option_word_h tcp_option_02;
    tcp_option_word_h tcp_option_03;
    tcp_option_word_h tcp_option_04;
    tcp_option_word_h tcp_option_05;
    tcp_option_word_h tcp_option_06;
    tcp_option_word_h tcp_option_07;
    tcp_option_word_h tcp_option_08;
    tcp_option_word_h tcp_option_09;
    tcp_option_word_h tcp_option_10;

    udp_h udp;
}

enum bit<32> protocol_id_t {
    /* Layer 2 */
    ETHERNET    = 0x00000001,
    VLAN        = 0x00000002,

    /* Layer 3 */
    IPV4        = 0x00000010,
    IPV6        = 0x00000020,

    ARP         = 0x00000040,
    ICMP        = 0x00000080,
    
    GOOSE       = 0x00000100,

    /* Layer 4 */
    TCP         = 0x00001000,
    UDP         = 0x00002000
}

struct ingress_metadata_t {
    // Packet Info
    @padding bit<(8 - PORT_ID_WIDTH % 8)> _pad1;
    PortId_t port;

    // Layer 7 header + payload length
    bit<16> payload_length;

    // Routing
    bit<8> src_network_id;
    bit<8> dst_network_id;

    // ACL
    bit<32> protocol_flags;

    bit<32> src_id;
    bit<32> src_sub_id;

    bit<16> src_manufacturer_id;
    bit<16> src_model_id;
    bit<128> src_ip_address;
    bit<16> src_port;
    bool valid_src;

    bit<32> dst_id;
    bit<32> dst_sub_id;

    bit<16> dst_manufacturer_id;
    bit<16> dst_model_id;
    bit<128> dst_ip_address;
    bit<16> dst_port;
    bool valid_dst;

    bit<16> ace_from_id;
    bit<16> ace_to_id;

    protocol_validator_id_t from_protocol_id;
    protocol_validator_id_t to_protocol_id;

    bit<8> validator_flags; // Flags that are not protocol dependent
    bit<8> protocol_validator_flags; // Flags that are protocol dependent
}

struct egress_headers_t {
    /* -------- Metadata -------- */
    egress_in_metadata_h egress_meta;

    /* -------- Layer 2 -------- */
    ethernet_h ethernet;
    monitoring_h monitoring;
    vlan_h vlan;

    /* -------- Layer 3 -------- */
    ipv4_h ipv4;
    ipv6_h ipv6;

    arp_h arp;
    icmp_h icmp;

    /* -------- Layer 4 -------- */
    tcp_h tcp;
    tcp_option_word_h tcp_option_01;
    tcp_option_word_h tcp_option_02;
    tcp_option_word_h tcp_option_03;
    tcp_option_word_h tcp_option_04;
    tcp_option_word_h tcp_option_05;
    tcp_option_word_h tcp_option_06;
    tcp_option_word_h tcp_option_07;
    tcp_option_word_h tcp_option_08;
    tcp_option_word_h tcp_option_09;
    tcp_option_word_h tcp_option_10;

    udp_h udp;

    /* -------- Layer 7 -------- */

    // ENIP
    enip_h enip;

    // MODBUS
    modbus_h modbus;
    modbus_exception_h modbus_exception;

    // OPCUA
    opcua_h opcua;
    opcua_error_h opcua_error;
    opcua_asymmetric_algorithm_h opcua_asymmetric_algorithm;
    // opcua_symmetric_algorithm_h opcua_symmetric_algorithm;

    opcua_security_policy_uri_1_h opcua_security_policy_uri_1;
    opcua_security_policy_uri_2_h opcua_security_policy_uri_2;
    opcua_security_policy_uri_3_h opcua_security_policy_uri_3;
    opcua_security_policy_uri_4_h opcua_security_policy_uri_4;
    opcua_security_policy_uri_5_h opcua_security_policy_uri_5;
    opcua_security_policy_uri_6_h opcua_security_policy_uri_6;
    opcua_security_policy_uri_7_h opcua_security_policy_uri_7;

    // GOOSE
    goose_h goose;
}

struct egress_metadata_t {
    bit<8> weird_payload;

    protocol_validator_id_t from_protocol_id;
    protocol_validator_id_t to_protocol_id;

    bit<8> validator_mask;
    bit<8> protocol_validator_mask;
}

#endif