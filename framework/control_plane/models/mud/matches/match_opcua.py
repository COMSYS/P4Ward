"""Mud ace match opcua"""

from __future__ import annotations
from typing import Any, Union
from enum import Enum

from framework.control_plane.models.mud import InvalidMudProfileError
from framework.control_plane.models.mud.matches.match import MudMatch

class MudOpcUASecurityLevel(Enum):
    LOW = 0
    MEDIUM = 1
    HIGH = 2

class MudMatchOpcUA(MudMatch):
    """Mud match opcua"""

    disable_deprecated_security_policies: bool
    security_level: MudOpcUASecurityLevel

    def __init__(self) -> None:
        super().__init__()

        self.disable_deprecated_security_policies = True
        self.security_level = MudOpcUASecurityLevel.MEDIUM

    def load_from_json(self, json: dict[str, Any], extensions: list[str]):
        try:
            if isinstance((disable_deprecated_security_policies := json.get("disable-deprecated-security-policies")), bool):
                self.disable_deprecated_security_policies = disable_deprecated_security_policies
            elif disable_deprecated_security_policies is not None:
                raise TypeError("disable-deprecated-security-policies")
            
            if isinstance((security_level := json.get("security-level")), str):
                if security_level == "low":
                    self.security_level = MudOpcUASecurityLevel.LOW
                elif security_level == "medium":
                    self.security_level = MudOpcUASecurityLevel.MEDIUM
                elif security_level == "high":
                    self.security_level = MudOpcUASecurityLevel.HIGH
                else:
                    raise TypeError("security-level")
            elif type is not None:
                raise TypeError("security-level")
        except KeyError as error:
            raise InvalidMudProfileError(
                f"MUD Profile ACE MODBUS match {error} entry is missing."
            ) from error
        except TypeError as error:
            raise InvalidMudProfileError(
                f"MUD Profile ACE MODBUS match {error} entry is invalid."
            ) from error
