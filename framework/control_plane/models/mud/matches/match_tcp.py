"""Mud ace match tcp"""

from __future__ import annotations
from typing import Any, Union
from enum import Enum

from framework.control_plane.models.mud import InvalidMudProfileError
from framework.control_plane.models.mud.matches.match import MudMatch


class MudTcpInitiationDirection(Enum):
    """Tcp connection initiation direction"""

    FROM_DEVICE = 1
    TO_DEVICE = 2


class MudTcpPortRange:
    """Tcp Port range"""

    min: int
    max: int

    def __init__(self) -> None:
        self.min = 0
        self.max = 65535


class MudMatchTcp(MudMatch):
    """Mud match tcp"""

    # TCP init direction
    initiation_direction: Union[MudTcpInitiationDirection, None]

    source_port: Union[int, MudTcpPortRange, None]
    destination_port: Union[int, MudTcpPortRange, None]

    def __init__(self) -> None:
        super().__init__()

        self.initiation_direction = None
        self.source_port = None
        self.destination_port = None

    def load_from_json(self, json: dict[str, Any], extensions: list[str]):
        try:
            if isinstance((in_di := json.get("ietf-mud:direction-initiated")), str):
                if in_di == "from-device":
                    self.initiation_direction = MudTcpInitiationDirection.FROM_DEVICE
                elif in_di == "to-device":
                    self.initiation_direction = MudTcpInitiationDirection.TO_DEVICE
                else:
                    raise TypeError("ietf-mud:direction-initiated")
            elif in_di is not None:
                raise TypeError("ietf-mud:direction-initiated")

            if isinstance((source_port_obj := json.get("source-port")), dict):
                if source_port_obj["operator"] == "eq":
                    if isinstance((port := source_port_obj["port"]), int):
                        self.source_port = port
                    else:
                        raise TypeError("port")
                elif source_port_obj["operator"] == "range":
                    if "port-range" not in extensions:
                        raise InvalidMudProfileError("Port range extension is not registered. Consider adding the 'port-range' extension.")

                    self.source_port = MudTcpPortRange()
                    if isinstance((min_port := source_port_obj["min-port"]), int):
                        self.source_port.min = min_port
                    else:
                        raise TypeError("min-port")
                    if isinstance((max_port := source_port_obj["max-port"]), int):
                        self.source_port.max = max_port
                    else:
                        raise TypeError("max-port")
            elif source_port_obj is not None:
                raise TypeError("source-port")

            if isinstance((destination_port_obj := json.get("destination-port")), dict):
                if destination_port_obj["operator"] == "eq":
                    if isinstance((port := destination_port_obj["port"]), int):
                        self.destination_port = port
                    else:
                        raise TypeError("port")
                elif destination_port_obj["operator"] == "range":
                    if "port-range" not in extensions:
                        raise InvalidMudProfileError("Port range extension is not registered. Consider adding the 'port-range' extension.")
                    
                    self.destination_port = MudTcpPortRange()
                    if isinstance((min_port := destination_port_obj["min-port"]), int):
                        self.destination_port.min = min_port
                    else:
                        raise TypeError("min-port")
                    if isinstance((max_port := destination_port_obj["max-port"]), int):
                        self.destination_port.max = max_port
                    else:
                        raise TypeError("max-port")
            elif destination_port_obj is not None:
                raise TypeError("destination-port")

        except KeyError as error:
            raise InvalidMudProfileError(
                f"MUD Profile ACE TCP match {error} entry is missing."
            ) from error
        except TypeError as error:
            raise InvalidMudProfileError(
                f"MUD Profile ACE TCP match {error} entry is invalid."
            ) from error
