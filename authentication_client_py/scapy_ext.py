"""Scapy Extension"""

from __future__ import annotations
from enum import IntEnum


class EtherType(IntEnum):
    EAPoL = 0x888E
    ROUTER_HELLO = 0xFFFF


class EAPoLType(IntEnum):
    EAP_PACKET = 0x00
    START = 0x01
    LOGOFF = 0x02
    KEY = 0x03
    ASF = 0x04


class EAPCode(IntEnum):
    REQUEST = 0x01
    RESPONSE = 0x02
    SUCCESS = 0x03
    FAILURE = 0x04


class EAPType(IntEnum):
    IDENTITY = 0x01
    MD5 = 0x04
    OTP = 0x05
