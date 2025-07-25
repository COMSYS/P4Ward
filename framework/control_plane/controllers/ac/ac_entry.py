"""Access Control entry and properties"""

from __future__ import annotations
from typing import Any, Union
from enum import Enum, IntEnum
from ipaddress import (
    IPv4Network,
    IPv6Network,
)

from framework.control_plane.helper import CRC16, CRC32
from framework.control_plane.controllers.ac.extensions import AcGooseExtension


class AcDirection(Enum):
    """Acl entry direction"""

    FROM = 0
    TO = 1

class AcProtocolId(IntEnum):
    """Protocol id used to define acl protocol

    Remarks:
        Bit flags are used
    """

    # Layer 2
    ETHERNET = 0x0000_0_00_1
    VLAN = 0x0000_0_00_2

    # Layer 3
    IPV4 = 0x0000_0_01_0
    IPV6 = 0x0000_0_02_0

    ARP = 0x0000_0_04_0
    ICMP = 0x0000_0_08_0

    GOOSE = 0x0000_0_10_0

    # Layer 4
    TCP = 0x0000_1_00_0
    UDP = 0x0000_2_00_0

class AcProtocolValidatorId(IntEnum):
    """Protocol id used to verify protocol

    Remarks:
        Bit flags are used
    """

    NO_PROTOCOL = 0
    UNDEFINED = 1
    ENIP = 2
    MODBUS = 3
    OPCUA = 4
    GOOSE = 5

class AcProtocolMask(int):
    """Protocol mask"""

    def __new__(cls, *protocol_ids: AcProtocolId):
        protocol_mask = int(0)
        for protocol_id in protocol_ids:
            protocol_mask = protocol_mask | int(protocol_id)
        return super(AcProtocolMask, cls).__new__(cls, protocol_mask)

    def __str__(self) -> str:
        result: list[str] = []

        if (self & AcProtocolId.ETHERNET) != 0:
            result.append("ETH")
        if (self & AcProtocolId.VLAN) != 0:
            result.append("VLAN")

        if (self & AcProtocolId.IPV4) != 0:
            result.append("IPv4")
        if (self & AcProtocolId.IPV6) != 0:
            result.append("IPv6")
        if (self & AcProtocolId.ARP) != 0:
            result.append("ARP")
        if (self & AcProtocolId.ICMP) != 0:
            result.append("ICMP")

        if (self & AcProtocolId.GOOSE) != 0:
            result.append("GOOSE")

        if (self & AcProtocolId.TCP) != 0:
            result.append("TCP")
        if (self & AcProtocolId.UDP) != 0:
            result.append("UDP")

        return ", ".join(result)

class AcAction(Enum):
    """ACL entry action"""

    # Accept packet
    ACCEPT = 1

    # Drop packet without sending icmp message
    DROP = 2

    # Drop packet while sending icmp message
    # Currently not supported
    REJECT = 3

class AcSubnet:
    """Network definition"""

    addresses: Union[IPv4Network, IPv6Network]

    def __init__(self, address: bytes, size: int) -> None:
        self.address = address
        self.size = size

class AcPortRange:
    """Port range definition"""

    min: Union[int, None]
    max: Union[int, None]

    def __init__(self, min: Union[int, None], max: Union[int, None]) -> None:
        self.min = min
        self.max = max
    
    @classmethod
    def from_tuple(cls, range: tuple[int, int]) -> AcPortRange:
        return AcPortRange(range[0], range[1])
    
    @classmethod
    def from_port(cls, port: int) -> AcPortRange:
        return AcPortRange(port, port)
    
    def get_tuple(self) -> tuple[int, int]:
        return (
            self.min if self.min is not None else 0,
            self.max if self.max is not None else 65535,
        )

    def __str__(self) -> str:
        return f"({self.min if self.min is not None else 0}, {self.max if self.max is not None else 0})"

class AcTcpInitiationDirection(IntEnum):
    """ACL tcp initiation direction"""

    FROM = 0
    TO = 1

class AcValidatorFlags(IntEnum):
    """Validator flags used during protocol validation

    Remarks:
        Bit flags are used
    """

    # NOTE: We use negated flags here, because we want the default behaviour to not interfere with traffic.
    # If is ACL entry specifically specifies that it is not a client or server packet.
    IS_NOT_CLIENT = 0x01
    IS_NOT_SERVER = 0x02
    DISABLE_WRITE = 0x03

class AcEntry:
    """Access Control entry

    Remarks:
        Properties that have been marked as none match every value
    """

    groups: dict[str, set[str]]

    # Trafic direction (in or out)
    direction: AcDirection

    # Packet handling action
    action: AcAction

    # Source controller id
    src_controller_name: Union[str, None]
    # Source manufacturer id
    src_manufacturer_name: Union[str, None]
    # Source model id
    src_model_name: Union[str, None]

    # Destination controller id
    dst_controller_name: Union[str, None]
    # Destination manufacturer id
    dst_manufacturer_name: Union[str, None]
    # Destination model id
    dst_model_name: Union[str, None]

    # Protocol mask
    protocol_mask: Union[AcProtocolMask, None]

    # Source ip network
    src_network: Union[IPv4Network, IPv6Network, int, None]
    # Source port range
    src_port: Union[AcPortRange, None]

    # Destination ip network
    dst_network: Union[IPv4Network, IPv6Network, int, None]
    # Destination port range
    dst_port: Union[AcPortRange, None]

    tcp_initiation_direction: Union[AcTcpInitiationDirection, None]
    protocol_validator_id: Union[AcProtocolValidatorId, None]
    validator_flags: int
    protocol_validator_flags: int

    # Extensions
    goose_ext: Union[AcGooseExtension, None]

    def __init__(
        self,
        direction: AcDirection,
        action: AcAction,
        protocol_mask: AcProtocolMask,
        src_controller_name: Union[str, None] = None,
        src_manufacturer_name: Union[str, None] = None,
        src_model_name: Union[str, None] = None,
        dst_controller_name: Union[str, None] = None,
        dst_manufacturer_name: Union[str, None] = None,
        dst_model_name: Union[str, None] = None,
        src_network: Union[IPv4Network, IPv6Network, int, None] = None,
        src_port: Union[int, AcPortRange, None] = None,
        dst_network: Union[IPv4Network, IPv6Network, int, None] = None,
        dst_port: Union[int, AcPortRange, None] = None,
        tcp_initiation_direction: Union[AcTcpInitiationDirection, None] = None,
        protocol_validator_id: Union[AcProtocolValidatorId, None] = None,
        validator_flags: int = 0,
        protocol_validator_flags: int = 0,
    ) -> None:
        self.groups = {}

        self.direction = direction
        self.action = action
        self.protocol_mask = protocol_mask if protocol_mask != 0 else None
        self.src_controller_name = src_controller_name
        self.src_manufacturer_name = src_manufacturer_name
        self.src_model_name = src_model_name
        self.dst_controller_name = dst_controller_name
        self.dst_manufacturer_name = dst_manufacturer_name
        self.dst_model_name = dst_model_name
        self.src_network = src_network

        if src_port is AcPortRange or src_port is None:
            self.src_port = src_port
        elif isinstance(src_port, int):
            self.src_port = AcPortRange.from_port(src_port)

        self.dst_network = dst_network

        if dst_port is AcPortRange or dst_port is None:
            self.dst_port = dst_port
        elif isinstance(dst_port, int):
            self.dst_port = AcPortRange.from_port(dst_port)

        self.tcp_initiation_direction = tcp_initiation_direction
        self.protocol_validator_id = protocol_validator_id
        self.validator_flags = validator_flags
        self.protocol_validator_flags = protocol_validator_flags

        self.goose_ext = None
    
    def __hash__(self) -> int:
        return (
            self.direction,
            self.action,
            self.src_controller_name,
            self.src_manufacturer_name,
            self.src_model_name,
            self.dst_controller_name,
            self.dst_manufacturer_name,
            self.dst_model_name,
            self.protocol_mask,
            self.src_network,
            self.src_port,
            self.dst_network,
            self.dst_port
        ).__hash__()

    def get_id_bytes(self) -> bytes:
        return (self.__hash__() & 0xFFFF).to_bytes(2, "big")

    def get_protocol_mask_bytes(self) -> bytes:
        protocol_mask = int(self.protocol_mask) if self.protocol_mask is not None else 0
        return (protocol_mask & 0xFFFFFFFF).to_bytes(4, "big")

    def get_src_controller_id(self) -> int:
        return (
            CRC32(self.src_controller_name.encode())
            if self.src_controller_name is not None
            else 0
        )

    def get_src_controller_id_bytes(self) -> bytes:
        return self.get_src_controller_id().to_bytes(4, "big")

    def get_src_manufacturer_id(self) -> int:
        return (
            CRC16(self.src_manufacturer_name.encode())
            if self.src_manufacturer_name is not None
            else 0
        )

    def get_src_manufacturer_id_bytes(self) -> bytes:
        return self.get_src_manufacturer_id().to_bytes(2, "big")

    def get_src_model_id(self) -> int:
        return (
            CRC16(self.src_model_name.encode())
            if self.src_model_name is not None
            else 0
        )

    def get_src_model_id_bytes(self) -> bytes:
        return self.get_src_model_id().to_bytes(2, "big")

    def get_dst_controller_id(self) -> int:
        return (
            CRC32(self.dst_controller_name.encode())
            if self.dst_controller_name is not None
            else 0
        )

    def get_dst_controller_id_bytes(self) -> bytes:
        return self.get_dst_controller_id().to_bytes(4, "big")

    def get_dst_manufacturer_id(self) -> int:
        return (
            CRC16(self.dst_manufacturer_name.encode())
            if self.dst_manufacturer_name is not None
            else 0
        )

    def get_dst_manufacturer_id_bytes(self) -> bytes:
        return self.get_dst_manufacturer_id().to_bytes(2, "big")

    def get_dst_model_id(self) -> int:
        return (
            CRC16(self.dst_model_name.encode())
            if self.dst_model_name is not None
            else 0
        )

    def get_dst_model_id_bytes(self) -> bytes:
        return self.get_dst_model_id().to_bytes(2, "big")
    
    def update(self, new_entry: AcEntry) -> bool:
        require_update: bool = False
        
        if self.tcp_initiation_direction != new_entry.tcp_initiation_direction:
            self.tcp_initiation_direction = None
            require_update = True
        
        if self.protocol_validator_id != new_entry.protocol_validator_id:
            self.protocol_validator_id = None
            require_update = True

        if self.validator_flags != new_entry.validator_flags:
            self.validator_flags = self.validator_flags & new_entry.validator_flags
            require_update = True

        if self.protocol_validator_flags != new_entry.protocol_validator_flags:
            self.protocol_validator_flags = self.protocol_validator_flags & new_entry.protocol_validator_flags
            require_update = True
        
        for (g, s) in new_entry.groups.items():
            if (g2 := self.groups.get(g)) is None:
                self.groups[g] = s
            else:
                g2.update(s)
        
        return require_update

    def __str__(self) -> str:
        result = f"{self.direction.name} {self.action.name}\n"

        result += "src:"
        if self.src_network is not None:
            result += f" {self.src_network}"
        if self.src_port is not None:
            result += f" {self.src_port}"
        if (
            self.src_controller_name is not None
            or self.src_manufacturer_name is not None
            or self.src_model_name is not None
        ):
            result += f" ({'_' if self.src_controller_name is None else self.src_controller_name}#{self.get_src_controller_id()}, {'_' if self.src_manufacturer_name is None else self.src_manufacturer_name}#{self.get_src_manufacturer_id()}, {'_' if self.src_model_name is None else self.src_model_name}#{self.get_src_model_id()})"
        result += "\n"

        result += "dst:"
        if self.dst_network is not None:
            result += f" {self.dst_network}"
        if self.dst_port is not None:
            result += f" {self.dst_port}"
        if (
            self.dst_controller_name is not None
            or self.dst_manufacturer_name is not None
            or self.dst_model_name is not None
        ):
            result += f" ({'_' if self.dst_controller_name is None else self.dst_controller_name}#{self.get_dst_controller_id()}, {'_' if self.dst_manufacturer_name is None else self.dst_manufacturer_name}#{self.get_dst_manufacturer_id()}, {'_' if self.dst_model_name is None else self.dst_model_name}#{self.get_dst_model_id()})"
        result += "\n"

        if self.protocol_mask is not None:
            result += f"protocol: {self.protocol_mask.__str__()}\n"

        return result
