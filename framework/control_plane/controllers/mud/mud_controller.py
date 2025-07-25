"""MUD controller"""

from __future__ import annotations
from typing import Union
import logging
import asyncio
from ipaddress import (
    ip_network,
    IPv4Address,
    IPv4Network,
    IPv4Interface,
    IPv6Address,
    IPv6Network,
    IPv6Interface,
)
from urllib.parse import urlparse
import typing

from framework.control_plane.tracing import TRACER
from framework.control_plane.models.mud.access_control import MudEndpointType
from framework.control_plane.models.mud.matches.match_tcp import MudTcpInitiationDirection
from framework.control_plane.models.mud.mud_profile import MudProfile, MudAccessControlList
from framework.control_plane.models.mud.matches.match_tcp import MudTcpPortRange
from framework.control_plane.models.mud.matches.match_udp import MudUdpPortRange
from framework.control_plane.models.mud.matches.match_opcua import MudOpcUASecurityLevel
from framework.control_plane.controllers.controller import Controller
from framework.control_plane.controllers.ac.ac_entry import (
    AcEntry,
    AcDirection,
    AcAction,
    AcProtocolMask,
    AcProtocolId,
    AcProtocolValidatorId,
    AcPortRange,
    AcTcpInitiationDirection,
    AcValidatorFlags,
)
from framework.control_plane.controllers.ac.extensions import AcGooseExtension

if typing.TYPE_CHECKING:
    from framework.control_plane.switch import Switch


class MudProfileError(Exception):
    """MUD profile error"""


class MudProfileUnsupportedError(Exception):
    """MUD profile feature not supported"""


class MudProfileNotDefinedError(Exception):
    """MUD profile is not defined"""


class MudProfileAmbiguousError(Exception):
    """MUD profile ambiguous"""


MUD_ACL_GROUP = "mud-contoller"
MUD_ACL_INDEPENDENT_SUB_GROUP = "independent"


class MudController(Controller):
    """MUD management controller"""

    _independent_profiles: set[str]

    def __init__(self, switch: "Switch") -> None:
        super().__init__(switch)

        self._independent_profiles = set()

    async def load_preload(self):
        if self._switch.preload.mud is not None:
            for profile in self._switch.preload.mud.profiles:
                mud_profile = await self.get_profile(profile.url)
                if mud_profile is not None:
                    self.enable_profile(profile.port, None, profile.ip_address, mud_profile)
            for url in self._switch.preload.mud.independent_profiles:
                profile = await self.get_profile(url)
                if profile is not None:
                    self.enable_profile(None, None, None, profile)

    async def get_profile(self, url: str) -> Union[MudProfile, None]:
        """Get mud profile using mud url

        Args:
            url (str): URL of the mud profile

        Returns:
            Union[MudProfile, None]: MUD Profile or none if it does not exist
        """
        raise NotImplementedError()

    def enable_profile(
        self,
        port: Union[int, None],
        id: Union[int, None],
        address: Union[IPv4Address, IPv6Address, None],
        profile: MudProfile,
    ):
        """Enable MUD profile

        Args:
            port (int): Device Port
            address (Union[IPv4Address, IPv6Address]): Device ip address
            url (str): MUD profile url
        """

        TRACER.info(f"Enabling MUD profile for '{address}': start")

        interface: Union[IPv4Interface, IPv6Interface, None] = None

        if address is not None and profile.independent != True:  # "DEPENDENT" Profile
            logging.debug("Enable profile '%s' for '%s'.", profile.url, address)

            if isinstance(address, IPv4Address):
                interface = IPv4Interface(
                    (
                        address,
                        (
                            32
                            if port is None
                            else self._switch.get_port_ipv4_network(port).prefixlen
                        ),
                    )
                )
            elif isinstance(address, IPv6Address):
                interface = IPv6Interface(
                    (
                        address,
                        (
                            128
                            if port is None
                            else self._switch.get_port_ipv6_network(port).prefixlen
                        ),
                    )
                )
            else:
                raise TypeError("Internal type error.")
        else:  # INDEPENDENT Profile
            if profile.url in self._independent_profiles:
                return
            self._independent_profiles.add(profile.url)

            logging.debug("Enable independent profile '%s'.", profile.url)

        if (manufacturer_name := profile.manufacturer_name) is None:
            manufacturer_name = urlparse(profile.url).netloc

        access_control_list_entries: list[AcEntry] = []

        # Parse from device policies
        if profile.from_device_policy.acl is not None:
            for name in profile.from_device_policy.acl.access_lists:
                if (acl := profile.access_control_lists.get(name)) is not None:
                    access_control_list_entries.extend(
                        self._parse_mud_acl(
                            acl,
                            AcDirection.FROM,
                            id,
                            interface,
                            profile.controller_name,
                            manufacturer_name,
                        )
                    )

        # Parse to device policies
        if profile.to_device_policy.acl is not None:
            for name in profile.to_device_policy.acl.access_lists:
                if (acl := profile.access_control_lists.get(name)) is not None:
                    access_control_list_entries.extend(
                        self._parse_mud_acl(
                            acl,
                            AcDirection.TO,
                            id,
                            interface,
                            profile.controller_name,
                            manufacturer_name,
                        )
                    )

        for access_control_list_entry in access_control_list_entries:
            self._switch.acl.add_entry(access_control_list_entry)

        TRACER.info(f"Enabling MUD profile for '{address}': end")

    def _parse_mud_acl(
        self,
        acl: MudAccessControlList,
        direction: AcDirection,
        device_id: Union[int, None],
        device_interface: Union[IPv4Interface, IPv6Interface, None],
        device_controller_name: Union[str, None],
        device_manufacturer_name: str,
    ) -> list[AcEntry]:
        device_network: Union[IPv4Network, IPv6Network, None] = None
        if device_interface is not None:
            device_network = device_interface.network

        global_validator_flags: set[int] = set()

        # Generate global validator flags for packet direction filtering
        if acl.self_type is not None:
            if acl.self_type == MudEndpointType.CLIENT:
                if direction == AcDirection.TO:
                    global_validator_flags.add(AcValidatorFlags.IS_NOT_CLIENT)
                elif direction == AcDirection.FROM:
                    global_validator_flags.add(AcValidatorFlags.IS_NOT_SERVER)
            elif acl.self_type == MudEndpointType.SERVER:
                if direction == AcDirection.TO:
                    global_validator_flags.add(AcValidatorFlags.IS_NOT_SERVER)
                elif direction == AcDirection.FROM:
                    global_validator_flags.add(AcValidatorFlags.IS_NOT_CLIENT)

        access_control_list_entries = []

        for entry in acl.entries:
            action: AcAction = AcAction.ACCEPT

            protocol_ids: set[AcProtocolId] = set()

            controller_name: Union[str, None] = None
            manufacturer_name: Union[str, None] = None
            model_name: Union[str, None] = None

            addresses: list[Union[IPv4Network, IPv6Network, None]] = []
            src_port: Union[int, None] = None
            dst_port: Union[int, None] = None

            tcp_initiation_direction: Union[AcTcpInitiationDirection, None] = None
            protocol_verification_id: Union[AcProtocolValidatorId, None] = None

            validator_flags: set[int] = set(global_validator_flags)
            protocol_validator_flags: set[int] = set()

            goose_extension: Union[AcGooseExtension, None] = None

            match_count: int = 0

            # Always add ethernet
            protocol_ids.add(AcProtocolId.ETHERNET)

            if entry.mud_match is not None:
                match_count += 1

                if entry.mud_match.same_manufacturer:
                    if manufacturer_name is not None:
                        raise MudProfileAmbiguousError(
                            "MUD entry manufacturer is ambiguous."
                        )
                    manufacturer_name = device_manufacturer_name

                if entry.mud_match.my_controller:
                    if controller_name is not None:
                        raise MudProfileAmbiguousError(
                            "MUD entry controller is ambiguous."
                        )
                    controller_name = device_controller_name

                if entry.mud_match.local_networks:
                    if device_network is None:
                        raise MudProfileUnsupportedError(
                            "Independent MUD profile nannot use MUD entry local networks."
                        )

                    addresses.append(device_network)

                if entry.mud_match.controller is not None:
                    if controller_name is not None:
                        raise MudProfileAmbiguousError(
                            "MUD entry controller is ambiguous."
                        )
                    controller_name = entry.mud_match.controller

                if entry.mud_match.manufacturer is not None:
                    if manufacturer_name is not None:
                        raise MudProfileAmbiguousError(
                            "MUD entry manufacturer is ambiguous."
                        )
                    manufacturer_name = entry.mud_match.manufacturer

                if entry.mud_match.model is not None:
                    if model_name is not None:
                        raise MudProfileAmbiguousError("MUD entry model is ambiguous.")
                    model_name = entry.mud_match.model

            ############ ARP ############
            if entry.arp_match:
                match_count += 1
                protocol_ids.add(AcProtocolId.ARP)

                if entry.arp_match.disable_request == True:
                    validator_flags.add(0x08) # DISABLE REQUEST

                if entry.arp_match.disable_reply == True:
                    validator_flags.add(0x10) # DISABLE REPLY

            ############ IPv4 ############
            if entry.ipv4_match:
                match_count += 1
                protocol_ids.add(AcProtocolId.IPV4)

                if entry.ipv4_match.source_dns_name is not None:
                    if direction == AcDirection.FROM:
                        raise MudProfileAmbiguousError(
                            "MUD ipv4 source dns match is ambiguous. Avoid specifying a source dns name for FROM polices."
                        )

                    if (
                        address := self._switch.config.dns.ipv4_constants.get(
                            entry.ipv4_match.source_dns_name
                        )
                    ) is not None:
                        addresses.append(ip_network(address))
                    else:
                        raise MudProfileNotDefinedError(
                            "MUD ipv4 domain name '{entry.ipv4_match.source_dns_name}' is not defined."
                        )

                if entry.ipv4_match.destination_dns_name is not None:
                    if direction == AcDirection.TO:
                        raise MudProfileAmbiguousError(
                            "MUD ipv4 destination dns match is ambiguous. Avoid specifying a destination dns name for TO polices."
                        )

                    if (
                        address := self._switch.config.dns.ipv4_constants.get(
                            entry.ipv4_match.destination_dns_name
                        )
                    ) is not None:
                        addresses.append(ip_network(address))
                    else:
                        raise MudProfileNotDefinedError(
                            "MUD ipv4 domain name '{entry.ipv4_match.destination_dns_name}' is not defined."
                        )

                if entry.ipv4_match.protocol is not None:
                    if entry.ipv4_match.protocol == 6:
                        protocol_ids.add(AcProtocolId.TCP)
                    elif entry.ipv4_match.protocol == 17:
                        protocol_ids.add(AcProtocolId.UDP)
                    else:
                        raise MudProfileUnsupportedError(
                            f"MUD ipv4 protocol '{hex(entry.ipv4_match.protocol)}' is not supported."
                        )

            ############ IPv6 ############
            if entry.ipv6_match:
                match_count += 1
                protocol_ids.add(AcProtocolId.IPV6)

                if entry.ipv6_match.source_dns_name is not None:
                    if direction == AcDirection.FROM:
                        raise MudProfileAmbiguousError(
                            "MUD ipv6 source dns match is ambiguous. Avoid specifying a source dns name for FROM polices."
                        )

                    if (
                        address := self._switch.config.dns.ipv6_constants.get(
                            entry.ipv6_match.source_dns_name
                        )
                    ) is not None:
                        addresses.append(ip_network(address))
                    else:
                        raise MudProfileNotDefinedError(
                            "MUD ipv6 domain name '{entry.ipv6_match.source_dns_name}' is not defined."
                        )

                if entry.ipv6_match.destination_dns_name is not None:
                    if direction == AcDirection.TO:
                        raise MudProfileAmbiguousError(
                            "MUD ipv6 destination dns match is ambiguous. Avoid specifying a destination dns name for TO polices."
                        )

                    if (
                        address := self._switch.config.dns.ipv6_constants.get(
                            entry.ipv6_match.destination_dns_name
                        )
                    ) is not None:
                        addresses.append(ip_network(address))
                    else:
                        raise MudProfileNotDefinedError(
                            "MUD ipv6 domain name '{entry.ipv6_match.destination_dns_name}' is not defined."
                        )

                if entry.ipv6_match.protocol is not None:
                    if entry.ipv6_match.protocol == 6:
                        protocol_ids.add(AcProtocolId.TCP)
                    elif entry.ipv6_match.protocol == 17:
                        protocol_ids.add(AcProtocolId.UDP)
                    else:
                        raise MudProfileUnsupportedError(
                            f"MUD ipv4 protocol '{hex(entry.ipv6_match.protocol)}' is not supported."
                        )

            ############ ICMP ############
            if entry.icmp_match:
                match_count += 1
                protocol_ids.add(AcProtocolId.ICMP)

                if entry.icmp_match.disable_requests == True:
                    validator_flags.add(0x08) # DISABLE REQUEST
                if entry.icmp_match.disable_replies == True:
                    validator_flags.add(0x10) # DISABLE REPLY
                
                if entry.icmp_match.disable_echo == True:
                    protocol_validator_flags.add(0x01) # DISABLE ECHO

                if entry.icmp_match.disable_destination_unreachable == True:
                    protocol_validator_flags.add(0x02) # DISABLE DESTINATION UNREACHABLE

                if entry.icmp_match.disable_redirect == True:
                    protocol_validator_flags.add(0x04) # DISABLE REDIRECT

                if entry.icmp_match.disable_router_advertisement == True:
                    protocol_validator_flags.add(0x08) # DISABLE ROUTER ADVERTISEMENT

                if entry.icmp_match.disable_router_solicitation == True:
                    protocol_validator_flags.add(0x10) # DISABLE ROUTER SOLICITATION

                if entry.icmp_match.disable_time_exceeded == True:
                    protocol_validator_flags.add(0x20) # DISABLE TIME EXCEEDED

                if entry.icmp_match.disable_bad_header == True:
                    protocol_validator_flags.add(0x40) # DISABLE BAD HEADER

                if entry.icmp_match.disable_timestamp == True:
                    protocol_validator_flags.add(0x80) # DISABLE TIMESTAMP


            ############ TCP ############
            if entry.tcp_match:
                match_count += 1
                protocol_ids.add(AcProtocolId.TCP)

                if entry.tcp_match.initiation_direction is not None:
                    if (
                        entry.tcp_match.initiation_direction
                        == MudTcpInitiationDirection.FROM_DEVICE
                    ):
                        tcp_initiation_direction = AcTcpInitiationDirection.FROM
                    elif (
                        entry.tcp_match.initiation_direction
                        == MudTcpInitiationDirection.TO_DEVICE
                    ):
                        tcp_initiation_direction = AcTcpInitiationDirection.TO

                if entry.tcp_match.source_port is not None:
                    if isinstance(entry.tcp_match.source_port, int):
                        src_port = entry.tcp_match.source_port
                    elif entry.tcp_match.source_port is MudTcpPortRange:
                        raise MudProfileUnsupportedError(
                            "MUD tcp port ranges are not supported."
                        )
                        src_port = AcPortRange.from_tuple(
                            entry.tcp_match.source_port.get_tuple()
                        )

                if entry.tcp_match.destination_port is not None:
                    if isinstance(entry.tcp_match.destination_port, int):
                        dst_port = entry.tcp_match.destination_port
                    elif entry.tcp_match.destination_port is MudTcpPortRange:
                        raise MudProfileUnsupportedError(
                            "MUD tcp port ranges are not supported."
                        )
                        dst_port = AcPortRange.from_tuple(
                            entry.tcp_match.destination_port.get_tuple()
                        )

            ############ UDP ############
            if entry.udp_match:
                match_count += 1
                protocol_ids.add(AcProtocolId.UDP)

                if entry.udp_match.source_port is not None:
                    if isinstance(entry.udp_match.source_port, int):
                        src_port = entry.udp_match.source_port
                    elif entry.udp_match.source_port is MudUdpPortRange:
                        raise MudProfileUnsupportedError(
                            "MUD udp port ranges are not supported."
                        )
                        src_port = AcPortRange.from_tuple(
                            entry.udp_match.source_port.get_tuple()
                        )

                if entry.udp_match.destination_port is not None:
                    if isinstance(entry.udp_match.destination_port, int):
                        dst_port = entry.udp_match.destination_port
                    elif entry.udp_match.destination_port is MudUdpPortRange:
                        raise MudProfileUnsupportedError(
                            "MUD udp port ranges are not supported."
                        )
                        dst_port = AcPortRange.from_tuple(
                            entry.udp_match.destination_port.get_tuple()
                        )

            ############ ENIP ############
            if entry.enip_match:
                match_count += 1

                if protocol_verification_id is not None:
                    raise MudProfileAmbiguousError(
                        "MUD application layer is ambiguous."
                    )

                if (
                    AcProtocolId.UDP not in protocol_ids
                    and AcProtocolId.TCP not in protocol_ids
                ):
                    raise MudProfileError(
                        "ENIP requires tcp or udp protocol. Consider specifying a valid layer 4 protocol."
                    )

                if acl.self_type is not None:
                    if AcProtocolId.TCP in protocol_ids:
                        if acl.self_type == MudEndpointType.CLIENT:
                            if dst_port is None:
                                dst_port = 44818
                        elif acl.self_type == MudEndpointType.SERVER:
                            if src_port is None:
                                src_port = 44818
                    elif AcProtocolId.UDP in protocol_ids:
                        if acl.self_type == MudEndpointType.CLIENT:
                            if dst_port is None:
                                dst_port = 2222
                        elif acl.self_type == MudEndpointType.SERVER:
                            if src_port is None:
                                src_port = 2222

                protocol_verification_id = AcProtocolValidatorId.ENIP

            ############ MODBUS ############
            if entry.modbus_match:
                match_count += 1

                if protocol_verification_id is not None:
                    raise MudProfileAmbiguousError(
                        "MUD application layer is ambiguous."
                    )

                if AcProtocolId.TCP not in protocol_ids:
                    raise MudProfileError(
                        "MODBUS requires tcp protocol. Consider specifying a valid layer 4 protocol."
                    )

                if acl.self_type is not None:
                    if acl.self_type == MudEndpointType.CLIENT:
                        if dst_port is None:
                            dst_port = 502
                    elif acl.self_type == MudEndpointType.SERVER:
                        if src_port is None:
                            src_port = 502

                protocol_verification_id = AcProtocolValidatorId.MODBUS

                if entry.modbus_match.read_only == True:
                    validator_flags.add(0x04) # DISABLE WRITE <=> READ-ONLY

                if entry.modbus_match.disable_extensions == True:
                    protocol_validator_flags.add(0x01) # DISABLE EXTENSIONS

                if entry.modbus_match.disable_coils == True:
                    protocol_validator_flags.add(0x02) # DISABLE COILS

                if entry.modbus_match.disable_discrete_inputs == True:
                    protocol_validator_flags.add(0x04) # DISABLE DISCRETE INPUTS

                if entry.modbus_match.disable_holding_registers == True:
                    protocol_validator_flags.add(0x08) # DISABLE HOLDING REGISTERS

                if entry.modbus_match.disable_input_registers == True:
                    protocol_validator_flags.add(0x10) # DISABLE INPUT REGISTERS

                if entry.modbus_match.disable_file_records == True:
                    protocol_validator_flags.add(0x20) # DISABLE FILE RECORDS

                if entry.modbus_match.disable_fifo == True:
                    protocol_validator_flags.add(0x40) # DISABLE FIFO

                if entry.modbus_match.disable_device_identification == True:
                    protocol_validator_flags.add(0x80) # DISABLE DEVICE IDENTIFICATION

            ############ OPCUA ############
            if entry.opcua_match:
                match_count += 1

                if protocol_verification_id is not None:
                    raise MudProfileAmbiguousError(
                        "MUD application layer is ambiguous."
                    )

                if AcProtocolId.TCP not in protocol_ids:
                    raise MudProfileError(
                        "OPCUA requires tcp protocol. Consider specifying a valid layer 4 protocol."
                    )

                protocol_verification_id = AcProtocolValidatorId.OPCUA

                if entry.opcua_match.security_level is not None:
                    if entry.opcua_match.security_level == MudOpcUASecurityLevel.MEDIUM:
                        protocol_validator_flags.add(0x01)  # DISABLE LOW
                    elif entry.opcua_match.security_level == MudOpcUASecurityLevel.HIGH:
                        protocol_validator_flags.add(0x01)  # DISABLE LOW
                        protocol_validator_flags.add(0x02)  # DISABLE MEDIUM

                if entry.opcua_match.disable_deprecated_security_policies == True:
                    protocol_validator_flags.add(0x03) # DISABLE DEPRECATED

            ############ GOOSE ############
            if entry.goose_match:
                match_count += 1
                protocol_ids.add(AcProtocolId.GOOSE)

                if protocol_verification_id is not None:
                    raise MudProfileAmbiguousError(
                        "MUD application layer is ambiguous."
                    )

                protocol_verification_id = AcProtocolValidatorId.GOOSE

                goose_extension = AcGooseExtension(entry.goose_match.app_id)

                if goose_extension.app_id is not None:
                    protocol_validator_flags.add(0x01) # VERIFY APP ID

            if len(addresses) == 0:
                addresses = [None]
            
            validator_flags_result = int(0)
            for flag in validator_flags:
                validator_flags_result = validator_flags_result | int(flag)
            
            protocol_validator_flags_result = int(0)
            for flag in protocol_validator_flags:
                protocol_validator_flags_result = protocol_validator_flags_result | int(flag)

            for address in addresses:
                src_network: Union[IPv4Network, IPv6Network, None]
                if isinstance(address, IPv4Address):
                    src_network = IPv4Network(address)
                elif isinstance(address, IPv6Address):
                    src_network = IPv6Network(address)
                else:
                    src_network = None

                ac_entry: AcEntry
                if direction == AcDirection.FROM:
                    ac_entry = AcEntry(
                        direction=AcDirection.FROM,
                        action=action,
                        protocol_mask=AcProtocolMask(*protocol_ids),
                        dst_controller_name=controller_name,
                        dst_manufacturer_name=manufacturer_name,
                        dst_model_name=model_name,
                        src_network=device_id,
                        src_port=src_port,
                        dst_network=src_network,
                        dst_port=dst_port,
                        tcp_initiation_direction=tcp_initiation_direction,
                        protocol_validator_id=protocol_verification_id,
                        validator_flags=validator_flags_result,
                        protocol_validator_flags=protocol_validator_flags_result,
                    )
                elif direction == AcDirection.TO:
                    ac_entry = AcEntry(
                        direction=AcDirection.TO,
                        action=action,
                        protocol_mask=AcProtocolMask(*protocol_ids),
                        src_controller_name=controller_name,
                        src_manufacturer_name=manufacturer_name,
                        src_model_name=model_name,
                        src_network=src_network,
                        src_port=src_port,
                        dst_network=device_id,
                        dst_port=dst_port,
                        tcp_initiation_direction=tcp_initiation_direction,
                        protocol_validator_id=protocol_verification_id,
                        validator_flags=validator_flags_result,
                        protocol_validator_flags=protocol_validator_flags_result,
                    )
                else:
                    raise MudProfileError("Invalid ACL direction.")

                ac_entry.goose_ext = goose_extension

                ac_entry.groups[MUD_ACL_GROUP] = {
                    str(
                        MUD_ACL_INDEPENDENT_SUB_GROUP
                        if device_interface is None
                        else device_interface.ip
                    )
                }
                access_control_list_entries.append(ac_entry)

        return access_control_list_entries

    def disable_profile(self, address: Union[IPv4Address, IPv6Address, None]):
        """Disable MUD profile"""

        TRACER.info(f"Disabling MUD profile for '{address}': start")

        if address is not None:  # "DEPENDENT" Profile
            logging.debug("Enable profile for '%s'", address)

            self._switch.acl.remove_entries(
                MUD_ACL_GROUP,
                str(address),
            )
        else:  # INDEPENDENT Profile
            logging.debug("Disable independent profiles")

            self._independent_profiles.clear()
            self._switch.acl.remove_entries(
                MUD_ACL_GROUP,
                str(MUD_ACL_INDEPENDENT_SUB_GROUP),
            )

        TRACER.info(f"Disabling MUD profile for '{address}': end")
