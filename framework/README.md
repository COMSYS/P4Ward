# Router Framework

The router framework consists of a P4 data plane (`data_plane`) and a Python control plane (`control_plane`). Both the data plane and the control plane are built around a stacked module design. Our current implementation contains the following modules: L2 forwarding, L3 routing, ARP, authentication, device management, access control, connection filtering, and MUD. Additional debugging and usability modules include the CLI and monitoring modules. 

![Router Modules](./modules.png "Router Framework Modules")

The idea behind the modular architecture is to encapsulate more and more functionalities using different module, thereby reducing complexity of each module and improving scalability.

## Overview Control Plane

- `config`: Loading and saving configuration files
    - `configs`: Main configuration file
    - `preloads`: Preload configuration file for specifying preloaded values and entries
    - `protocols`: Protocol specific configuration file for modifying protocol behavior (see protocol packet validation on the data plane).
- `controllers`: Framework controllers / modules
    - `ac`: Access Control module responsible for managing access control entries
        - `protocols`: Access control protocol extensions
    - `arp`: ARP module for managing ARP reply entries
    - `auth`: Authentication module
        - `local`: Child class for local authentication
        - `remote`: Child class for remote authentication
    - `cli`: CLI module
    - `device`: Device management module
    - `filter`: TCP connection filtering module
    - `l2`: L2 forwarding module
    - `l3`: L3 routing module
    - `monitoring`: Monitoring module
    - `mud`: Manufacturer Device Usage module
        - `local`: Child class for local MUD profiles
        - `remote`: Child class for remote MUD profiles
- `data_plane`: Data plane interface abstraction
- `models`: Data models used by the framework
    - `mud`: Manufacturer Device Usage model

## Overview Data Plane

- `switch.p4`: Data plane definition
- `ingress.p4`: Ingress Pipeline
- `egress.p4`: Egress Pipeline
- `types.p4`: Types and structures used by the ingress and egress pipeline
- `headers`: Protocol header definitions
    - `ethernet.p4`: Ethernet Protocol
    - `ipv4.p4`: IPv4 Protocol
    - `ipv6.p4`: IPv6 Protocol
    - etc...
- `controls`: Data plane modules
    - `validator`: Protocol packet validators
        - `arp_validator.p4`: ARP protocol packet validator
        - `enip_validator.p4`: ENIP protocol packet validator
        - `goose_validator.p4`: GOOSE protocol packet validator
        - `icmp_validator.p4`: ICMP protocol packet validator
        - `modbus_validator.p4`: Modbus/TCP protocol packet validator
        - `opcua_validator.p4`: OPC-UA protocol packet validator
    - `acl.p4`: Access Control List and Connection Filtering modules
    - `arp.p4`: ARP module
    - `auth.p4`: Authentication module
    - `device_validator.p4`: Device validator module (counterpart to the device management module)
    - `routing.p4`: L2 forwarding and L3 routing modules