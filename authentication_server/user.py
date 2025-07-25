from __future__ import annotations
from typing import Union
from enum import Enum
from ipaddress import IPv4Address, IPv6Address, ip_address


class AuthenticationMethod(Enum):
    MD5 = 1
    OTP_MD5 = 2
    OTP_SHA1 = 3
    OTP_SHA2 = 4
    OTP_SHA3 = 5


class User:
    """User credentials and attributes"""

    name: str
    password: str
    auth_method: AuthenticationMethod
    ip_address: Union[IPv4Address, IPv6Address]
    mud_profile: str
    attributes: dict[str, str]

    # Cache
    value: bytes

    def __init__(self, name: str, password: str, authentication_method: AuthenticationMethod, ip_address: Union[IPv4Address, IPv6Address], profile: str, attributes: dict[str, str]) -> None:
        self.name = name
        self.password = password
        self.auth_method = authentication_method
        self.ip_address = ip_address
        self.mud_profile = profile
        self.attributes = attributes
        
    def get_attribute(self, key: str) -> Union[str, None]:
        """Get attribute

        Args:
            key (str): Attribute key

        Returns:
            Union[str, None]: Attribute value or none
        """
        return self.attributes.get(key)

    def get_attribute_or_default(self, key: str, default: str) -> str:
        """Get attribute or default value

        Args:
            key (str): Attribute key
            default (str): Default value

        Returns:
            str: Attribute value
        """
        if (value := self.attributes.get(key)) is not None:
            return value
        else:
            return default
