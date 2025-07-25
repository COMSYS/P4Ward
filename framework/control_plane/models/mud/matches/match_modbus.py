"""Mud ace match modbus"""

from __future__ import annotations
from typing import Any, Union
from enum import Enum

from framework.control_plane.models.mud import InvalidMudProfileError
from framework.control_plane.models.mud.matches.match import MudMatch


class MudMatchModBus(MudMatch):
    """Mud match modbus"""

    read_only: Union[bool, None]

    disable_coils: Union[bool, None]
    disable_discrete_inputs: Union[bool, None]
    disable_holding_registers: Union[bool, None]
    disable_input_registers: Union[bool, None]
    disable_file_records: Union[bool, None]
    disable_fifo: Union[bool, None]
    disable_device_identification: Union[bool, None]
    disable_extensions: Union[bool, None]

    def __init__(self) -> None:
        super().__init__()

        self.read_only = None
        self.disable_coils = None
        self.disable_discrete_inputs = None
        self.disable_holding_registers = None
        self.disable_input_registers = None
        self.disable_file_records = None
        self.disable_fifo = None
        self.disable_device_identification = None
        self.disable_extensions = None

    def load_from_json(self, json: dict[str, Any], extensions: list[str]):
        try:
            if isinstance((read_only := json.get("read-only")), bool):
                self.read_only = read_only
            elif read_only is not None:
                raise TypeError("read-only")
            
            if isinstance((disable_coils := json.get("disable-coils")), bool):
                self.disable_coils = disable_coils
            elif disable_coils is not None:
                raise TypeError("disable-coils")
            
            if isinstance((disable_discrete_inputs := json.get("disable-discrete-inputs")), bool):
                self.disable_discrete_inputs = disable_discrete_inputs
            elif disable_discrete_inputs is not None:
                raise TypeError("discrete-inputs")
            
            if isinstance((disable_holding_registers := json.get("disable-holding-registers")), bool):
                self.disable_holding_registers = disable_holding_registers
            elif disable_holding_registers is not None:
                raise TypeError("disable-holding-registers")
            
            if isinstance((disable_input_registers := json.get("disable-input-registers")), bool):
                self.disable_input_registers = disable_input_registers
            elif disable_input_registers is not None:
                raise TypeError("disable-input-registers")
            
            if isinstance((disable_file_records := json.get("disable-file-records")), bool):
                self.disable_file_records = disable_file_records
            elif disable_file_records is not None:
                raise TypeError("disable-file-records")
            
            if isinstance((disable_fifo := json.get("disable-fifo")), bool):
                self.disable_fifo = disable_fifo
            elif disable_fifo is not None:
                raise TypeError("disable-fifo")
            
            if isinstance((disable_device_identification := json.get("disable-device-identification")), bool):
                self.disable_device_identification = disable_device_identification
            elif disable_device_identification is not None:
                raise TypeError("disable-device-identification")
            
            if isinstance((disable_extensions := json.get("disable-extensions")), bool):
                self.disable_extensions = disable_extensions
            elif disable_extensions is not None:
                raise TypeError("disable-extensions")
            
        except KeyError as error:
            raise InvalidMudProfileError(
                f"MUD Profile ACE MODBUS match {error} entry is missing."
            ) from error
        except TypeError as error:
            raise InvalidMudProfileError(
                f"MUD Profile ACE MODBUS match {error} entry is invalid."
            ) from error
