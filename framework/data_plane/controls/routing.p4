/* -*- P4_16 -*- */
#ifndef __CONTROLS_LAYER_2__
#define __CONTROLS_LAYER_2__

#include <core.p4>
#include <tna.p4>

#include "../types.p4"

control RoutingControl(
    inout ingress_headers_t headers,
    inout ingress_metadata_t meta,
    in ingress_intrinsic_metadata_t intr_meta,
    in ingress_intrinsic_metadata_from_parser_t parser_meta,
    inout ingress_intrinsic_metadata_for_deparser_t deparser_meta,
    inout ingress_intrinsic_metadata_for_tm_t traffic_manager_meta) {

    bool perform_l3_routing = false;

    action drop() {
        deparser_meta.drop_ctl = 1;
        exit;
    }

    /**** Layer 3 routing ****/

    // L3 route
    action l3_ipv4_route(MacAddress_t src_mac_address, MacAddress_t dst_mac_address, PortId_t port) {
        traffic_manager_meta.ucast_egress_port = port;

        headers.ethernet.src_address = src_mac_address;
        headers.ethernet.dst_address = dst_mac_address;

        headers.ipv4.ttl = headers.ipv4.ttl - 1;
    }

    action l3_ipv6_route(MacAddress_t src_mac_address, MacAddress_t dst_mac_address, PortId_t port) {
        traffic_manager_meta.ucast_egress_port = port;

        headers.ethernet.src_address = src_mac_address;
        headers.ethernet.dst_address = dst_mac_address;

        headers.ipv6.hop_limit = headers.ipv6.hop_limit - 1;
    }

    // Routing using IP addresses
    table l3_routing {
        key = {
            meta.dst_ip_address: lpm @name("dst_ip_address");
        }
        actions = {
            l3_ipv4_route;
            l3_ipv6_route;
            @defaultonly drop;
        }
        size = 1024;
        default_action = drop();
    }

    /**** Layer 2 forwarding ****/

    // L2 route
    action l2_network(bit<8> id) {
        meta.src_network_id = id;
    }

    table l2_network_id {
        key = {
            meta.port: exact @name("port");
        }
        actions = {
            l2_network;
            @defaultonly NoAction;
        }
        size = 128;
        default_action = NoAction();
    }

    // L2 route
    action l2_route(PortId_t port, bit<8> network_id) {
        traffic_manager_meta.ucast_egress_port = port;
        meta.dst_network_id = network_id;
    }

    // Broadcast on layer 2
    action l2_broadcast() {
        traffic_manager_meta.mcast_grp_a = (MulticastGroupId_t)meta.src_network_id;
        traffic_manager_meta.level2_exclusion_id = meta.port;
        meta.dst_network_id = meta.src_network_id;
    }

    // Pass to L3 routing using IP addresses
    // This is done when a network change occurs
    action pass_to_l3() {
        perform_l3_routing = true;
        meta.dst_network_id = meta.src_network_id;
    }

    // Forwarding using MAC addresses
    table l2_routing {
        key = {
            headers.ethernet.dst_address: exact @name("dst_mac_address");
        }
        actions = {
            l2_route;
            l2_broadcast;
            pass_to_l3;
            @defaultonly drop;
        }
        size = 1024;
        default_action = drop();
    }

    apply {
        // Perform L2 routing
        l2_network_id.apply();
        l2_routing.apply();

        if (perform_l3_routing) {
            // Perform L3 routing
            l3_routing.apply();
        }
    }

}

#endif
