"""Packet Metadata"""

from __future__ import annotations
from enum import IntEnum
from scapy.packet import Packet, bind_bottom_up
from scapy.layers.l2 import Ether
from scapy.layers.eap import EAPOL
from scapy.fields import ByteField, ShortField

class EAPMetadataType(IntEnum):
    """EAP metadata type"""

    MESSAGE = 0x01
    SUCCESS = 0x02
    FAILURE = 0x03
    ERROR = 0x04


class EAP_META(Packet):
    """EAP metadata sent from data-plane"""

    name = "EAP-META"
    fields_desc = [
        ByteField("type", 0),
        ShortField("port", 0),
    ]

bind_bottom_up(Ether, EAP_META)
bind_bottom_up(EAP_META, EAPOL)

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