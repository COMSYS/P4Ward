"""Modbus Protocol Configurator"""

from __future__ import annotations
from typing import Any, Union
import typing

from framework.control_plane.helper import *
from framework.control_plane.data_plane.table import DPTable

if typing.TYPE_CHECKING:
    from framework.control_plane.switch import Switch

VALIDATOR_FLAG_NONE = 0x00
VALIDATOR_FLAG_DISABLE_WRITE = 0x04

MODBUS_FLAG_NONE = 0x00
MODBUS_FLAG_DISABLE_EXTENSIONS = 0x01
MODBUS_FLAG_DISABLE_COILS = 0x02
MODBUS_FLAG_DISABLE_DISCRETE_INPUTS = 0x04
MODBUS_FLAG_DISABLE_HOLDING_REGISTERS = 0x08
MODBUS_FLAG_DISABLE_INPUT_REGISTERS = 0x10
MODBUS_FLAG_DISABLE_FILE_RECORD = 0x20
MODBUS_FLAG_DISABLE_FIFO = 0x40
MODBUS_FLAG_DISABLE_DEVICE_IDENTIFICATION = 0x80


def configure_modbus_protocol(switch: "Switch"):
    functions_table: DPTable = switch.data_plane.get_table(
        "Egress.modbus_validator.modbus_function_codes"
    )

    functions: dict[int, tuple[int, int]] = {}

    if switch.protocol.modbus.load_defaults:
        # Read Coils
        functions[0x01] = (
            VALIDATOR_FLAG_NONE,
            MODBUS_FLAG_DISABLE_COILS,
        )

        # Read Discrete Inputs
        functions[0x02] = (
            VALIDATOR_FLAG_NONE,
            MODBUS_FLAG_DISABLE_DISCRETE_INPUTS,
        )

        # Read Multiple Holding Registers
        functions[0x03] = (
            VALIDATOR_FLAG_NONE,
            MODBUS_FLAG_DISABLE_HOLDING_REGISTERS,
        )

        # Read Input Registers
        functions[0x04] = (
            VALIDATOR_FLAG_NONE,
            MODBUS_FLAG_DISABLE_INPUT_REGISTERS,
        )

        # Write Single Coil
        functions[0x05] = (
            VALIDATOR_FLAG_DISABLE_WRITE,
            MODBUS_FLAG_DISABLE_COILS,
        )

        # Write Single Holding Register
        functions[0x06] = (
            VALIDATOR_FLAG_DISABLE_WRITE,
            MODBUS_FLAG_DISABLE_HOLDING_REGISTERS,
        )

        # Write Multiple Coils
        functions[0x0F] = (
            VALIDATOR_FLAG_DISABLE_WRITE,
            MODBUS_FLAG_DISABLE_COILS,
        )

        # Write Multiple Holding Registers
        functions[0x10] = (
            VALIDATOR_FLAG_DISABLE_WRITE,
            MODBUS_FLAG_DISABLE_HOLDING_REGISTERS,
        )

        # Read File Record
        functions[0x14] = (
            VALIDATOR_FLAG_NONE,
            MODBUS_FLAG_DISABLE_FILE_RECORD,
        )

        # Write File Record
        functions[0x15] = (
            VALIDATOR_FLAG_DISABLE_WRITE,
            MODBUS_FLAG_DISABLE_FILE_RECORD,
        )

        # Mask Write Register
        functions[0x16] = (
            VALIDATOR_FLAG_DISABLE_WRITE,
            MODBUS_FLAG_DISABLE_HOLDING_REGISTERS,
        )

        # Read / Write Multiple Registers
        functions[0x17] = (
            VALIDATOR_FLAG_DISABLE_WRITE,
            MODBUS_FLAG_DISABLE_HOLDING_REGISTERS,
        )

        # Read FIFO Queue
        functions[0x18] = (VALIDATOR_FLAG_NONE, MODBUS_FLAG_DISABLE_FIFO)

        # Read Device Identification
        functions[0x2B] = (
            VALIDATOR_FLAG_NONE,
            MODBUS_FLAG_DISABLE_DEVICE_IDENTIFICATION,
        )

    for entry in switch.protocol.modbus.function_codes:
        validator_flags: int = 0x00
        protocol_flags: int = 0x00

        if entry.set_disable_write_flag:
            validator_flags = validator_flags | VALIDATOR_FLAG_DISABLE_WRITE

        if entry.set_disable_extensions_flag:
            protocol_flags = protocol_flags | MODBUS_FLAG_DISABLE_EXTENSIONS

        if entry.set_disable_coils_flag:
            protocol_flags = protocol_flags | MODBUS_FLAG_DISABLE_COILS

        if entry.set_disable_discrete_inputs_flag:
            protocol_flags = protocol_flags | MODBUS_FLAG_DISABLE_DISCRETE_INPUTS

        if entry.set_disable_holding_registers_flag:
            protocol_flags = protocol_flags | MODBUS_FLAG_DISABLE_HOLDING_REGISTERS

        if entry.set_disable_input_registers_flag:
            protocol_flags = protocol_flags | MODBUS_FLAG_DISABLE_INPUT_REGISTERS

        if entry.set_disable_file_record_flag:
            protocol_flags = protocol_flags | MODBUS_FLAG_DISABLE_FILE_RECORD

        if entry.set_disable_fifo_flag:
            protocol_flags = protocol_flags | MODBUS_FLAG_DISABLE_FIFO

        if entry.set_disable_device_identification_flag:
            protocol_flags = protocol_flags | MODBUS_FLAG_DISABLE_DEVICE_IDENTIFICATION

        functions[entry.value] = (validator_flags, protocol_flags)

    for value, flags in functions.items():
        functions_table.entry_add(
            {
                "value": value,
            },
            "set_flags",
            {
                "validator_mask": flags[0],
                "protocol_validator_mask": flags[1],
            },
        )

    exceptions_table: DPTable = switch.data_plane.get_table(
        "Egress.modbus_validator.modbus_exceptions"
    )

    exceptions: dict[int, None] = {}

    if switch.protocol.modbus.load_defaults:
        # ILLEGAL FUNCTION
        exceptions[0x01] = None

        # ILLEGAL DATA ADDRESS
        exceptions[0x02] = None

        # ILLEGAL DATA VALUE
        exceptions[0x03] = None

        # SERVER DEVICE FAILURE
        exceptions[0x04] = None

        # ACKNOWLEDGE
        exceptions[0x05] = None

        # SERVER DEVICE BUSY
        exceptions[0x06] = None

        # MEMORY PARITY ERROR
        exceptions[0x08] = None

        # GATEWAY PATH UNAVAILABLE
        exceptions[0x0A] = None

        # GATEWAY TARGET DEVICE FAILED TO RESPOND
        exceptions[0x0B] = None

    for entry in switch.protocol.modbus.exception_codes:
        exceptions[entry.value] = None

    for value, flags in exceptions.items():
        exceptions_table.entry_add(
            {
                "value": value,
            },
            "NoAction",
            {},
        )
