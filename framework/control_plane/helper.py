"""Helper"""

from typing import Union
from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network
import crcmod

CRC16 = crcmod.mkCrcFun(0x18005, initCrc=0, xorOut=0xFFFF)
CRC32 = crcmod.mkCrcFun(0x104C11DB7, initCrc=0, xorOut=0xFFFFFFFF)

IPV4_TO_IPV6_ROOT = bytes(
    [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF]
)
IPV4_TO_IPV6_MASK_ROOT = bytes(
    [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]
)


def ip_to_128(address: Union[IPv4Address, IPv6Address]) -> bytes:
    if isinstance(address, IPv4Address):
        return IPV4_TO_IPV6_ROOT + address.packed
        # return address.packed
    elif isinstance(address, IPv6Address):
        return address.packed
    else:
        raise RuntimeError("Internal type error")


def ip_to_128_mask(address: Union[IPv4Network, IPv6Network]) -> bytes:
    if isinstance(address, IPv4Network):
        return IPV4_TO_IPV6_MASK_ROOT + address.netmask.packed
    elif isinstance(address, IPv6Network):
        return address.netmask.packed
    else:
        raise RuntimeError("Internal type error")

def ip_to_128_prefix_length(address: Union[IPv4Network, IPv6Network]) -> int:
    if isinstance(address, IPv4Network):
        return 96 + address.prefixlen
    elif isinstance(address, IPv6Network):
        return address.prefixlen
    else:
        raise RuntimeError("Internal type error")
